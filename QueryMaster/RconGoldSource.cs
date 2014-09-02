using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;

namespace QueryMaster
{
    class RconGoldSource : Rcon
    {
        internal static readonly byte[] RconChIdQuery = { 0xFF, 0xFF, 0xFF, 0xFF, 0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65, 0x20, 0x72, 0x63, 0x6f, 0x6e };

        internal static readonly byte[] RconQuery = { 0xFF, 0xFF, 0xFF, 0xFF, 0x72, 0x63, 0x6f, 0x6e, 0x20 };//+<challenge id>+"<rcon password>"+<value>
        internal string RConPass = string.Empty;
        internal UdpQuery socket;
        private RconGoldSource(IPEndPoint address)
        {
            socket = new UdpQuery(address, 3000, 3000);
        }

        internal string ChallengeId = string.Empty;
        internal static Rcon Authorize(IPEndPoint address, string pass)
        {
            RconGoldSource Obj = new RconGoldSource(address);
            Obj.GetChallengeId();
            Obj.RConPass = pass;
            if (!Obj.SendCommand("").Contains("Bad rcon_password"))
            {
                return Obj;
            }
            if (Obj.socket != null)
                Obj.socket.Dispose();
            return null;
        }

        public override string SendCommand(string command)
        {
            byte[] rconMsg = Util.MergeByteArrays(RconQuery, Util.StringToBytes(ChallengeId), Util.StringToBytes(" \"" + RConPass + "\" " + command));
            byte[] recvData = new byte[2000];
            recvData = socket.GetResponse(rconMsg, EngineType.GoldSource);
            return Util.BytesToString(recvData).Remove(0, 1);
        }

        private void GetChallengeId()
        {
            Parser parser = new Parser(socket.GetResponse(RconChIdQuery, EngineType.GoldSource));
            ChallengeId = parser.ReadString().Split(' ')[2].Trim();
        }



        public override void Dispose()
        {
            if (socket != null)
                socket.Dispose();
        }


        public override void AddlogAddress(string ip, ushort port)
        {
            SendCommand("logaddress_add " + ip + " " + port);
        }

        public override void RemovelogAddress(string ip, ushort port)
        {
            SendCommand("logaddress_del " + ip + " " + port);
        }
    }
}
