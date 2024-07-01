// #define VALIDATE_PACKETS
// #define DEBUG

using NanoSockets;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading;

namespace Networking
{
    public enum ConnectionState
    {
        Connecting = 0,
        Connected = 1,
        Disconnected = 2
    }

    public enum DisconnectReason
    {
        Timeout,
        NegativeSequence,
        RemoteBufferTooBig,
        Other
    }

    public interface IHeaderWriter
    {
        void PutUnreliableHeader(ByteBuffer buffer);
        void ReadUnreliableHeader(ByteBuffer buffer);
    }

    public partial class Connection
    {
        internal ByteBuffer ReliableBuffer;
        internal ByteBuffer UnreliableBuffer;
        internal ByteBuffer AckBuffer;

#if DEBUG
        public ByteBuffer Current;
#endif

        public int PacketsPerSecond;
        public TimeSpan PacketsPerSecondTimeout;

        public IHeaderWriter HeaderWriter;

        public Address RemoteEndPoint;
        public NetManager Manager;
        public string Token;

        public DisconnectReason Reason;

        public DateTime PingSentAt;

        internal Dictionary<short, ByteBuffer> ReliablePackets = new Dictionary<short, ByteBuffer>();
        internal Dictionary<short, ByteBuffer> RemoteReliableOrderBuffer = new Dictionary<short, ByteBuffer>();

        private short Sequence = 1;
        public short NextRemoteSequence = 2;
        private int[] Window = new int[NetConstants.WindowSize / 32 + 1];

        public float TimeoutLeft = 120f;

        public int Ping = 50;

        public const int Mtu = 1200;
        public byte ConnectionId = 0;

        public static byte ConnectionPool = 0;

        public Connection Next;

        public QuickStringDictionary<uint> SymbolToIndex = new QuickStringDictionary<uint>(32);
        public QuickBag<String> IndexToSymbol = new QuickBag<string>(4);


        public QuickStringDictionary<uint> SymbolToIndexRemote = new QuickStringDictionary<uint>(32);
        public QuickBag<String> IndexToSymbolRemote = new QuickBag<string>(4);

        public byte[] EncryptionKey = new byte[16];
#if NET5_0_OR_GREATER
        public AesGcm AesEncryptor;
#endif

        public Connection()
        {
#if NET5_0_OR_GREATER
            AesEncryptor = new AesGcm(EncryptionKey);
#endif
        }


        public uint SymbolPool;

        public bool IsClosed
        {
            get
            {
                return State == ConnectionState.Disconnected;
            }
        }

        public Action Disconnected;

        public Action<ByteBuffer> PacketReceived;

        public ConnectionState State;

        public ByteBuffer BeginReliable()
        {
#if DEBUG
            if (Current != null) throw new NotSupportedException();
#endif

            if (ReliableBuffer == null)
            {
                ReliableBuffer = ConcurrentByteBufferPool.Acquire();
                ReliableBuffer.Connection = this;

                Sequence = (short)((Sequence + 1) % NetConstants.WindowSize);

                ReliableBuffer.Put((byte)PacketType.Reliable);
                ReliableBuffer.Put(Sequence);
                ReliableBuffer.Put(Manager.TickNumber);

                ReliableBuffer.Sequence = Sequence;
                ReliableBuffer.Reliable = true;
            }
#if DEBUG
            Current = ReliableBuffer;
#endif

            return ReliableBuffer;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Send(ByteBuffer buffer)
        {
            NetManager.Send(buffer);
        }

        public void PushAck(short sequence)
        {
            if (AckBuffer == null)
            {
                AckBuffer = ConcurrentByteBufferPool.Acquire();
                AckBuffer.Connection = this;
                AckBuffer.Reliable = false;

                AckBuffer.Put((byte)PacketType.Ack);
            }

            AckBuffer.Put(sequence);

            if (AckBuffer.Position > (Mtu - 2))
            {
                Send(AckBuffer);

                AckBuffer = null;
            }
        }

        public void ValidateEndOfPacket(ByteBuffer buffer, int packetId)
        {
#if VALIDATE_PACKETS
            if(buffer.GetByte() != 39){
                throw new NotSupportedException($"pacote {packetId} está quebrado!");
            }
#endif
        }

        public void EndReliable()
        {
#if DEBUG
            if (Current != ReliableBuffer) throw new NotSupportedException();
#endif

#if VALIDATE_PACKETS
            ReliableBuffer.Put((byte)(39));
#endif

            if (ReliableBuffer.Position >= Mtu)
            {
                ReliableBuffer.Size = ReliableBuffer.Position;

                ReliablePackets[ReliableBuffer.Sequence] = ReliableBuffer;

                Send(ReliableBuffer);

                ReliableBuffer = null;
            }
#if DEBUG
            Current = null;
#endif
        }

        public ByteBuffer BeginUnreliable()
        {
#if DEBUG
            if (Current != null) throw new NotSupportedException();
#endif
            if (UnreliableBuffer == null)
            {
                UnreliableBuffer = ConcurrentByteBufferPool.Acquire();
                UnreliableBuffer.Connection = this;

                UnreliableBuffer.Put((byte)PacketType.Unreliable);

                HeaderWriter.PutUnreliableHeader(UnreliableBuffer);

                UnreliableBuffer.Put(Manager.TickNumber);
                UnreliableBuffer.Reliable = false;
            }
#if DEBUG
            Current = UnreliableBuffer;
#endif

            return UnreliableBuffer;
        }

        public void EndUnreliable()
        {
#if DEBUG
            if (Current != UnreliableBuffer)
                throw new NotSupportedException();
#endif

#if VALIDATE_PACKETS
            UnreliableBuffer.Put((byte)(39));
#endif

            if (UnreliableBuffer.Position >= Mtu)
            {
                UnreliableBuffer.Size = UnreliableBuffer.Position;

                Send(UnreliableBuffer);

                UnreliableBuffer = null;
            }
#if DEBUG
            Current = null;
#endif
        }

        public void ProcessPacket(PacketType type, ByteBuffer buffer)
        {
            TimeoutLeft = Math.Max(15.0f, TimeoutLeft);

            try
            {
                switch (type)
                {
                    case PacketType.Ping:
                    case PacketType.Pong:
                        break;

                    case PacketType.Ack:
                        while (buffer.HasData)
                        {
                            short sequence = buffer.GetShort();
                            ByteBuffer temp;
#if UNITY_5_3_OR_NEWER
                       if(ReliablePackets.TryGetValue(sequence, out temp)){
                            if (temp.Connection == this)
                            {
                                Interlocked.Exchange(ref temp.Acked, 0);
                            }

                            ReliablePackets.Remove(sequence);
                       }
#else

                            if (ReliablePackets.Remove(sequence, out temp))
                            {
                                if (temp.Connection == this)
                                {
                                    Interlocked.Exchange(ref temp.Acked, 0);
                                }
                            }
#endif
                        }
                        break;

                    case PacketType.Reliable:
                        {
                            buffer.Reliable = true;

                            short sequence = buffer.GetShort();

                            /*
                            if (sequence <= 0 || sequence > NetConstants.WindowSize || NetConstants.RelativeSequenceNumber(NextRemoteSequence, sequence) >= 50)
                            {
                                ConcurrentByteBufferPool.Release(buffer);

                                //Disconnect(DisconnectReason.NegativeSequence);
                                return;
                            }
                            */

                            buffer.Sequence = sequence;

                            PushAck(sequence);

                            if ((Window[sequence / 32] & (1 << (sequence % 32))) == 0)
                            {
                                Window[sequence / 32] |= (1 << (sequence % 32));

                                int index = Math.Abs((NetConstants.HalfWindowSize + sequence) % NetConstants.WindowSize);

                                Window[index / 32] &= ~(1 << (index % 32));

                                if (buffer.Sequence == NextRemoteSequence)
                                {
                                    PacketReceived?.Invoke(buffer);

                                    NextRemoteSequence = (short)((NextRemoteSequence + 1) % NetConstants.WindowSize);

#if UNITY_5_3_OR_NEWER

                                    while (RemoteReliableOrderBuffer.TryGetValue(NextRemoteSequence, out ByteBuffer next))
                                    {
                                        RemoteReliableOrderBuffer.Remove(NextRemoteSequence);

                                        PacketReceived?.Invoke(next);

                                        NextRemoteSequence = (short)((NextRemoteSequence + 1) % NetConstants.WindowSize);

                                        ConcurrentByteBufferPool.Release(next);
                                    }
#else

                                    while (RemoteReliableOrderBuffer.Remove(NextRemoteSequence, out ByteBuffer next))
                                    {
                                        PacketReceived?.Invoke(next);

                                        NextRemoteSequence = (short)((NextRemoteSequence + 1) % NetConstants.WindowSize);

                                        ConcurrentByteBufferPool.Release(next);
                                    }
#endif
                                }
                                else
                                {
                                    RemoteReliableOrderBuffer.Add(sequence, buffer);

                                    if (RemoteReliableOrderBuffer.Count > 200)
                                    {
                                        Disconnect(DisconnectReason.RemoteBufferTooBig);
                                    }

#if DEBUG
                                    Console.WriteLine("Remote Buffer Size: " + RemoteReliableOrderBuffer.Count);
#endif

                                    return;
                                }
                            }

                        }
                        break;

                    case PacketType.Unreliable:
                        {
                            /*
#if DEBUG
                            if(Random.NextDouble() <= 0.5)
                                break;
#endif
                            */

                            HeaderWriter?.ReadUnreliableHeader(buffer);

                            PacketReceived?.Invoke(buffer);
                        }
                        break;
                }
            }
            catch(Exception ex)
            {
                Console.WriteLine($"{ex}");
            }

            ConcurrentByteBufferPool.Release(buffer);
        }

        public bool Update(float delta)
        {
            if (State == ConnectionState.Disconnected)
            {
                return true;
            }

            TimeoutLeft -= delta;

            if (TimeoutLeft <= 0)
            {
                Disconnect(DisconnectReason.Timeout);

                return true;
            }

            if (ReliableBuffer != null)
            {
                ReliablePackets[ReliableBuffer.Sequence] = ReliableBuffer;

                Send(ReliableBuffer);

                ReliableBuffer = null;
            }

            if (UnreliableBuffer != null)
            {
                Send(UnreliableBuffer);

                UnreliableBuffer = null;
            }

            if (AckBuffer != null)
            {
                Send(AckBuffer);

                AckBuffer = null;
            }

            return false;
        }

        public void Disconnect(DisconnectReason reason = DisconnectReason.Other)
        {
            if (State != ConnectionState.Disconnected)
            {
                Reason = reason;

                ByteBuffer response = ConcurrentByteBufferPool.Acquire();

                response.Connection = this;

                response.Put((byte)PacketType.Disconnected);

                Send(response);

                OnDisconnect();
            }
        }

        internal void OnDisconnect()
        {
            if (State != ConnectionState.Disconnected)
            {
                State = ConnectionState.Disconnected;

                if(UnreliableBuffer != null)
                {
                    ConcurrentByteBufferPool.Release(UnreliableBuffer);

                    UnreliableBuffer = null;
                }

                if(ReliableBuffer != null)
                {
                    ConcurrentByteBufferPool.Release(ReliableBuffer);

                    ReliableBuffer = null;
                }

                if (AckBuffer != null)
                {
                    ConcurrentByteBufferPool.Release(AckBuffer);

                    AckBuffer = null;
                }

                Disconnected?.Invoke();

                foreach (var buffer in ReliablePackets.Values)
                {
                    Interlocked.Exchange(ref buffer.Acked, 0);
                }

                foreach (var buffer in RemoteReliableOrderBuffer.Values)
                {
                    ConcurrentByteBufferPool.Release(buffer);
                }

                ReliablePackets.Clear();

                RemoteReliableOrderBuffer.Clear();
            }
        }
    }
}