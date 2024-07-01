/**
 * Binary network packet interface of communication between server and client
 * 
 * @author Andre Ferreira
 */

using System;
using System.Linq;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using Shared;
#if !UNITY_5_3_OR_NEWER
using ToS.Server;
#endif

namespace Networking
{
#if UNITY_5_3_OR_NEWER
    public abstract class PacketHandler
    {
        static readonly Dictionary<int, PacketHandler> Handlers = new Dictionary<int, PacketHandler>();

        public virtual ServerPacketType Type { get; }

        public abstract bool Consume(NetworkController ctrl, ByteBuffer buffer, uint tickNumber);

        static PacketHandler()
        {
            if (Handlers.Count <= 0)
            {
                foreach (Type t in AppDomain.CurrentDomain.GetAssemblies()
                    .SelectMany(t => t.GetTypes())
                    .Where(t => t.IsClass && t.Namespace == "Network.Packets"))
                {
                    if (Activator.CreateInstance(t) is PacketHandler packetHandler)
                    {
                        if (!Handlers.ContainsKey((int)packetHandler.Type) && packetHandler.Type != ServerPacketType.None)
                            Handlers.Add((int)packetHandler.Type, packetHandler);
                    }
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool HandlePacket(NetworkController ctrl, ByteBuffer buffer, ServerPacketType type, uint tickNumber)
        {
            return (Handlers.ContainsKey((int)type)) ? Handlers[(int)type].Consume(ctrl, buffer, tickNumber) : false;
        }
    }
#else
    public abstract class PacketHandler
    {
        static readonly Dictionary<int, PacketHandler> Handlers = new Dictionary<int, PacketHandler>();

        public virtual ClientPacketType Type { get; }

        public abstract void Consume(PlayerController ctrl, ByteBuffer buffer);

        static PacketHandler()
        {
            foreach (Type t in AppDomain.CurrentDomain.GetAssemblies()
                       .SelectMany(t => t.GetTypes())
                       .Where(t => t.IsClass && t.Namespace == "Network.Packets"))
            {
                if (Activator.CreateInstance(t) is PacketHandler packetHandler)
                {
                    if (!Handlers.ContainsKey((int)packetHandler.Type) && packetHandler.Type != ClientPacketType.None)
                        Handlers.Add((int)packetHandler.Type, packetHandler);
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool HandlePacket(PlayerController ctrl, ByteBuffer buffer, ClientPacketType type)
        {
            if (Handlers.ContainsKey((int)type)) 
            {
                Handlers[(int)type]?.Consume(ctrl, buffer);

                return true;
            }
            else
            {
                return false;
            }
        }
    }
#endif
}
