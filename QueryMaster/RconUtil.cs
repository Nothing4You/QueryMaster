﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace QueryMaster
{
    static class RconUtil
    {
        internal static byte[] GetBytes(RconSrcPacket packet)
        {
            packet.Size = 10 + packet.Body.Length;
            List<byte> y = new List<byte>(packet.Size + 4);
            y.AddRange(BitConverter.GetBytes(packet.Size));
            y.AddRange(BitConverter.GetBytes(packet.Id));
            y.AddRange(BitConverter.GetBytes(packet.Type));
            y.AddRange(Encoding.ASCII.GetBytes(packet.Body));
            //part of string
            y.Add(0x00);
            //end terminater
            y.Add(0x00);
            return y.ToArray();
        }

        internal static RconSrcPacket ProcessPacket(byte[] data)
        {
            RconSrcPacket packet = new RconSrcPacket();
            Parser parser = new Parser(data);
            packet.Size = parser.ReadInt();
            packet.Id = parser.ReadInt();
            packet.Type = parser.ReadInt();
            string s = Util.BytesToString(parser.GetUnParsedData());
            packet.Body = s.EndsWith("\0\0", StringComparison.Ordinal) ? s.Remove(s.Length - 3) : s;
            return packet;
        }
    }
}
