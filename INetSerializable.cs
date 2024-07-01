using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Networking
{
    public interface INetSerializable
    {
        void Write(ByteBuffer buffer);
        void Read(ByteBuffer buffer);
    }
}