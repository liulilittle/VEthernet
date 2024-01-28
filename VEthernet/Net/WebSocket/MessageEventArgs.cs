namespace VEthernet.Net.WebSocket
{
    using System;
    using System.Text;

    public class MessageEventArgs : EventArgs
    {
        private readonly static Encoding _encoding;

        static MessageEventArgs()
        {
            _encoding = Encoding.UTF8;
        }

        public OpCode Code
        {
            get;
            private set;
        }

        public bool IsText
        {
            get
            {
                return Code == OpCode.Text;
            }
        }

        public byte[] RawData
        {
            get;
            private set;
        }

        public string Message
        {
            get
            {
                if (!IsText)
                {
                    throw new InvalidOperationException();
                }
                return _encoding.GetString(RawData);
            }
        }

        public MessageEventArgs(OpCode code, byte[] raw)
        {
            this.Code = code;
            this.RawData = raw;
        }
    }
}
