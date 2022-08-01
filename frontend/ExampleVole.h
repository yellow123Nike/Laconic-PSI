#pragma once


#include "libOTe/Vole/SilentVoleReceiver.h"
#include "libOTe/Vole/SilentVoleSender.h"

namespace osuCrypto
{


    //template<typename OtExtSender, typename OtExtRecver>
    void Vole_example(Role role, int numOTs, int numThreads, std::string ip, std::string tag, CLP& cmd)
    {
#ifdef ENABLE_SILENT_VOLE

        if (numOTs == 0)
            numOTs = 1 << 20;
        using OtExtSender = SilentVoleSender;
        using OtExtRecver = SilentVoleReceiver;

        // get up the networking
        //role等于Sender则rr的会话模型为Server，否则为Client
        auto rr = role == Role::Sender ? SessionMode::Server : SessionMode::Client;
        IOService ios;
        //创建相互连接的会话
        Session  ep0(ios, ip, rr);
        PRNG prng(sysRandomSeed());

        // for each thread we need to construct a channel (socket) for it to communicate on.
        //对于每个线程都需要一个对应的通道
        std::vector<Channel> chls(numThreads);
        for (int i = 0; i < numThreads; ++i)
            chls[i] = ep0.addChannel();

        //bool mal = cmd.isSet("mal");
        OtExtSender sender;
        OtExtRecver receiver;

        bool fakeBase = cmd.isSet("fakeBase");
        //计时
        gTimer.setTimePoint("begin");

        auto routine = [&](int s, int sec, SilentBaseType type)
        {
            //计时
            Timer timer;
            u64 milli;

            // get a random number generator seeded from the system
            //为系统生成两个随机数
            PRNG prng(sysRandomSeed());
            PRNG pp(ZeroBlock);

            //如果是Receiver
            if (role == Role::Receiver)
            {
                gTimer.setTimePoint("recver.thrd.begin");
                //设置一个choice向量大小为numOTs
                std::vector<block> choice(numOTs);
                gTimer.setTimePoint("recver.msg.alloc0");

                // construct a vector to stored the received messages.
                //设置一个向量msgs存储接收到的消息. 
                //std::vector<block> msgs(numOTs);
                std::unique_ptr<block[]> backing(new block[numOTs]);
                span<block> msgs(backing.get(), numOTs);
                gTimer.setTimePoint("recver.msg.alloc1");
                //SilverConfigure设置
                //.configure() --> SilentVoleReceiver.cpp -->SilverConfigure()-->SilentOtExtSender.cpp
                receiver.configure(numOTs, sec);
                gTimer.setTimePoint("recver.config");

                //sync(chls[0], role);
                if (fakeBase)
                {
                    auto nn = receiver.baseOtCount();//返回base OT的数量
                    std::vector<std::array<block, 2>> baseSendMsgs(nn);
                    pp.get(baseSendMsgs.data(), baseSendMsgs.size());
                    receiver.setBaseOts(baseSendMsgs);
                }
                else
                {
                    receiver.genSilentBaseOts(prng, chls[0]);
                }
                sync(chls[0], role);
                auto b = timer.setTimePoint("start");
                receiver.setTimePoint("start");
                gTimer.setTimePoint("recver.genBase");

                // perform  numOTs random OTs, the results will be written to msgs.
                //生成向量c和b
                receiver.silentReceive(choice, msgs, prng, chls[0]);
                receiver.setTimePoint("finish");

                auto e = timer.setTimePoint("finish");
                milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - b).count();
            }
            //发送方
            else
            {
                gTimer.setTimePoint("sender.thrd.begin");

                //std::vector<std::array<block, 2>> msgs(numOTs);
                std::unique_ptr<block[]> backing(new block[numOTs]);
                span<block> msgs(backing.get(), numOTs);
                gTimer.setTimePoint("sender.msg.alloc");
                sender.configure(numOTs, sec);
                gTimer.setTimePoint("sender.config");
                block delta = prng.get();

                auto b = timer.setTimePoint("start");
                //sync(chls[0], role);
                if (fakeBase)
                {
                    auto nn = receiver.baseOtCount();
                    BitVector bits(nn); bits.randomize(prng);
                    std::vector<std::array<block, 2>> baseSendMsgs(nn);
                    std::vector<block> baseRecvMsgs(nn);
                    pp.get(baseSendMsgs.data(), baseSendMsgs.size());
                    for (u64 i = 0; i < nn; ++i)
                        baseRecvMsgs[i] = baseSendMsgs[i][bits[i]];
                    sender.setBaseOts(baseRecvMsgs, bits);
                }
                else
                {
                    sender.genSilentBaseOts(prng, chls[0]);
                }
                sync(chls[0], role);

                sender.setTimePoint("start");
                gTimer.setTimePoint("sender.genBase");

                // construct a vector to stored the random send messages. 

                // if delta OT is used, then the user can call the following 
                // to set the desired XOR difference between the zero messages
                // and the one messages.
                //
                //     senders[i].setDelta(some 128 bit delta);
                //

                // perform the OTs and write the random OTs to msgs.
                sender.silentSend(delta, msgs, prng, chls[0]);
                sender.setTimePoint("finish");

                auto e = timer.setTimePoint("finish");
                milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - b).count();

            }
            return milli;
        };

        cmd.setDefault("s", "2");
        cmd.setDefault("sec", "128");
        std::vector<int> ss = cmd.getMany<int>("s");
        std::vector<int> secs = cmd.getMany<int>("sec");
        u64 trials = cmd.getOr("trials", 1);
        auto mulType = (MultType)cmd.getOr("multType", (int)MultType::slv5);
        std::vector< SilentBaseType> types;

        receiver.mMultType = mulType;
        sender.mMultType = mulType;

        if (cmd.isSet("base"))
            types.push_back(SilentBaseType::Base);
        else if (cmd.isSet("baseExtend"))
            types.push_back(SilentBaseType::BaseExtend);
        else
            types.push_back(SilentBaseType::BaseExtend);

        for (auto s : ss)
            for (auto sec : secs)
                for (auto type : types)
                {
                    for (u64 tt = 0; tt < trials; ++tt)
                    {

                        chls[0].resetStats();

                        Timer sendTimer, recvTimer;

                        sendTimer.setTimePoint("start");
                        recvTimer.setTimePoint("start");

                        sender.setTimer(sendTimer);
                        receiver.setTimer(recvTimer);

                        auto milli = routine(s, sec, type);



                        u64 com = 0;
                        for (auto& c : chls)
                            com += (c.getTotalDataRecv() + c.getTotalDataSent());

                        std::string typeStr = "n ";
                        switch (type)
                        {
                        case SilentBaseType::Base:
                            typeStr = "b ";
                            break;
                            //case SilentBaseType::Extend:
                            //	typeStr = "e ";
                            //	break;
                        case SilentBaseType::BaseExtend:
                            typeStr = "be";
                            break;
                        default:
                            break;
                        }
                        if (role == Role::Sender)
                        {

                            lout << tag <<
                                " n:" << Color::Green << std::setw(6) << std::setfill(' ') << numOTs << Color::Default <<
                                " type: " << Color::Green << typeStr << Color::Default <<
                                " sec: " << Color::Green << std::setw(3) << std::setfill(' ') << sec << Color::Default <<
                                " s: " << Color::Green << s << Color::Default <<
                                "   ||   " << Color::Green <<
                                std::setw(6) << std::setfill(' ') << milli << " ms   " <<
                                std::setw(6) << std::setfill(' ') << com << " bytes" << std::endl << Color::Default;

                            if (cmd.getOr("v", 0) > 1)
                                lout << gTimer << std::endl;

                        }
                        if (cmd.isSet("v"))
                        {
                            if (role == Role::Sender)
                                lout << " **** sender ****\n" << sendTimer << std::endl;

                            if (role == Role::Receiver)
                                lout << " **** receiver ****\n" << recvTimer << std::endl;
                        }
                    }

                }

#endif
    }

}