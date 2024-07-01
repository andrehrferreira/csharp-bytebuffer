/**
 * Byte Buffer extension
 * 
 * @author Diego Guedes
 * @revision Andre Ferreira
 */

using Shared;
using System;
using System.Net;
using System.Threading;
#if UNITY_5_3_OR_NEWER
using UnityEngine;
#else
using System.Numerics;
#endif
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Networking
{
    public unsafe class ByteBuffer : IDisposable
    {
        static volatile int Counter = 0;

        public volatile bool IsDestroyed;

        public bool HasData
        {
            get { return Position < Size; }
        }

        public void Reset()
        {
            Position = 0;
            Size = 0;

            Connection = null;
            Next = null;

            QuantizeOffsetX = 0;
            QuantizeOffsetY = 0;
            QuantizeOffsetZ = 0;
        }

        public void Dispose()
        {
            if (Connection != null)
            {
                if (Reliable)                
                    Connection.EndReliable();                
                else                
                    Connection.EndUnreliable();
            }
            else
            {
                ConcurrentByteBufferPool.Release(this);
            }
        }

        ~ByteBuffer()
        {
            if (Data != null)
            {
#if UNITY_5_3_OR_NEWER
                Marshal.FreeHGlobal((IntPtr)Data);
#else
                NativeMemory.Free(Data);
#endif
                Data = null;

                IsDestroyed = true;
            }

            Interlocked.Decrement(ref Counter);
        }

        public int QuantizeOffsetX;
        public int QuantizeOffsetY;
        public int QuantizeOffsetZ;

        public int Position = 0;
        public int Size;
        public short Sequence;
        public uint TickNumber;

#if DEBUG
        public DateTime SentAt;
#endif
        public byte* Data;
        public volatile int Acked;
        public volatile bool Reliable;

        public Connection Connection;

        public ByteBuffer Next;

        const float FloatQuantizeFactor = 1.0f / 0.05f;
        const float FloatDequantizeFactor = 0.05f;

        const float PositionQuantizeFactor = 1.0f / 0.1f;
        const float PositionDequantizeFactor = 0.1f;


        public const int NONCE_LENGTH = 12; // in bytes
        public const int TAG_LENGTH = 16; // in bytes

        public void Decrypt()
        {
#if !UNITY_5_3_OR_NEWER
            if (AesGcm.IsSupported)
            {
                AesGcm aes = Connection.AesEncryptor;

                ReadOnlySpan<byte> nonce = new ReadOnlySpan<byte>(Data + Size - NONCE_LENGTH - TAG_LENGTH, NONCE_LENGTH);

                ReadOnlySpan<byte> tag = new ReadOnlySpan<byte>(Data + Size - TAG_LENGTH, TAG_LENGTH);

                int cipherSize = Size - TAG_LENGTH - NONCE_LENGTH - 1;

                Span<byte> cipher = new Span<byte>(Data + 1, cipherSize);

                aes.Decrypt(nonce, cipher, tag, cipher);

                Size = cipherSize + 1;

                Position = 0;
            }
            else
#endif
            {
                DecryptSoftwareFallback(Connection.EncryptionKey);
            }
        }

        public void DecryptSoftwareFallback(byte[] encryptionKey)
        {
            byte[] nonce = new byte[NONCE_LENGTH];
            byte[] tag = new byte[TAG_LENGTH];

            new Span<byte>(Data + Size - NONCE_LENGTH - TAG_LENGTH, NONCE_LENGTH).CopyTo(nonce);

            new Span<byte>(Data + Size - TAG_LENGTH, TAG_LENGTH).CopyTo(tag);

            int cipherSize = Size - TAG_LENGTH - NONCE_LENGTH - 1;

            var cipher = new ReadOnlySpan<byte>(Data + 1, cipherSize);

            var plaintextBytes = new byte[cipherSize];

            var bcCiphertext = new byte[cipherSize + TAG_LENGTH];

            cipher.CopyTo(new Span<byte>(bcCiphertext));

            tag.CopyTo(new Span<byte>(bcCiphertext, cipherSize, TAG_LENGTH));

            var blockCipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(encryptionKey), TAG_LENGTH * 8, nonce);
            blockCipher.Init(false, parameters);

            var offset = blockCipher.ProcessBytes(bcCiphertext, 0, bcCiphertext.Length, plaintextBytes, 0);

            blockCipher.DoFinal(plaintextBytes, offset);

            new Span<byte>(plaintextBytes).CopyTo(new Span<byte>(Data + 1, cipherSize));

            Size = cipherSize + 1;

            Position = 0;
        }

        public void EncryptSoftwareFallback(byte[] encryptionKey)
        {
            var nonce = new byte[NONCE_LENGTH];
            RandomNumberGenerator.Fill(nonce);

            var plaintextBytes = new byte[Size - 1];

            new Span<byte>(Data + 1, Size - 1).CopyTo(plaintextBytes.AsSpan());

            var bcCiphertext = new byte[plaintextBytes.Length + TAG_LENGTH];

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(encryptionKey), TAG_LENGTH * 8, nonce);


            cipher.Init(true, parameters);

            var offset = cipher.ProcessBytes(plaintextBytes, 0, plaintextBytes.Length, bcCiphertext, 0);
            cipher.DoFinal(bcCiphertext, offset);

            new Span<byte>(nonce).CopyTo(new Span<byte>(Data + Position, NONCE_LENGTH));

            Position += NONCE_LENGTH;

            var tag = new Span<byte>(bcCiphertext, plaintextBytes.Length, TAG_LENGTH);

            tag.CopyTo(new Span<byte>(Data + Position, TAG_LENGTH));

            Position += TAG_LENGTH;

            var data = new Span<byte>(bcCiphertext, 0, plaintextBytes.Length);

            data.CopyTo(new Span<byte>(Data + 1, plaintextBytes.Length));

            Size = Position;
            Position = 0;
        }

        public void Encrypt()
        {
#if !UNITY_5_3_OR_NEWER
            if (AesGcm.IsSupported)
            {
                AesGcm aes = Connection.AesEncryptor;

                Span<byte> nonce = new Span<byte>(Data + Position, NONCE_LENGTH);

                RandomNumberGenerator.Fill(nonce);

                Position += NONCE_LENGTH;

                Span<byte> tag = new(Data + Position, TAG_LENGTH);

                Position += TAG_LENGTH;

                var cipher = new Span<byte>(Data + 1, Size - 1);

                aes.Encrypt(nonce, cipher, cipher, tag);

                Size = Position;
            }
            else
#endif
            {
                EncryptSoftwareFallback(Connection.EncryptionKey);
            }
        }

        public ByteBuffer()
        {
#if UNITY_5_3_OR_NEWER
            Data = (byte*)Marshal.AllocHGlobal(Connection.Mtu * 3);
#else
            Data = (byte*)NativeMemory.Alloc(Connection.Mtu * 3);
#endif
            if (Interlocked.Increment(ref Counter) % 10 == 0)
            {
                Console.WriteLine("Allocated buffer count: " + Counter);
            }

        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Put(float value)
        {
            PutVar((int)(value * FloatQuantizeFactor));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Put(byte[] value, int maxLength = 800)
        {
            if (value == null)
            {
                PutVar((uint)0);
            }
            else
            {
                int length = Math.Min(maxLength, value.Length);

                PutVar((uint)length);

                fixed (byte* src = value)
                {
                    CustomCopy((void*)(Data + Position), (void*)(src), length);
                }

                Position += length;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Put(ulong value)
        {
            *(ulong*)(Data + Position) = value;

            Position += 8;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Put(int value)
        {
            *(int*)(Data + Position) = value;

            Position += 4;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Put(uint value)
        {
            *(uint*)(Data + Position) = value;

            Position += 4;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Put(ushort value)
        {
            *(ushort*)(Data + Position) = value;

            Position += 2;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Put(short value)
        {
            *(short*)(Data + Position) = value;

            Position += 2;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Put(long value)
        {
            *(long*)(Data + Position) = value;

            value += 8;
        }

        const float QuantizeFactor = (float)short.MaxValue / (float)(NetConstants.ChunkSize * 2);
        const float DequantizeFactor = (float)(NetConstants.ChunkSize * 2) / (float)short.MaxValue;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void PutQuantized(Vector3 value)
        {
#if UNITY_5_3_OR_NEWER
            Put((short)((value.x - QuantizeOffsetX) * QuantizeFactor));
            Put((short)((value.y - QuantizeOffsetY) * QuantizeFactor));
            Put((short)((value.z - QuantizeOffsetY) * QuantizeFactor));
#else
            Put((short)((value.X - QuantizeOffsetX) * QuantizeFactor));
            Put((short)((value.Y - QuantizeOffsetY) * QuantizeFactor));
            Put((short)((value.Z - QuantizeOffsetY) * QuantizeFactor));
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void PutPosition(Vector3 value)
        {
#if UNITY_5_3_OR_NEWER
            int x = ((int)(value.x * PositionQuantizeFactor) - QuantizeOffsetX);
            int y = ((int)(value.y * PositionQuantizeFactor) - QuantizeOffsetY);
            int z = ((int)(value.z * PositionQuantizeFactor) - QuantizeOffsetY);
#else
            int x = ((int)(value.X * PositionQuantizeFactor) - QuantizeOffsetX);
            int y = ((int)(value.Y * PositionQuantizeFactor) - QuantizeOffsetY);
            int z = ((int)(value.Z * PositionQuantizeFactor) - QuantizeOffsetY);
#endif

            PutVar(x);
            PutVar(y);
            PutVar(z);

            QuantizeOffsetX = x;
            QuantizeOffsetY = y;
            QuantizeOffsetY = z;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public Vector3 GetPosition()
        {
            int x = GetVarInt() + QuantizeOffsetX;
            int y = GetVarInt() + QuantizeOffsetY;
            int z = GetVarInt() - QuantizeOffsetZ;

            QuantizeOffsetX = x;
            QuantizeOffsetY = y;
            QuantizeOffsetZ = z;

            return new Vector3(x * PositionDequantizeFactor, y * PositionDequantizeFactor, z * PositionDequantizeFactor);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public Vector3 GetQuantized()
        {
            return new Vector3(
                QuantizeOffsetX + GetShort() * DequantizeFactor, 
                QuantizeOffsetY + GetShort() * DequantizeFactor, 
                QuantizeOffsetZ + GetShort() * DequantizeFactor
            );
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Put(sbyte value)
        {
            Data[Position] = (byte)value;
            Position++;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Put(byte value)
        {
            Data[Position] = value;
            Position++;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void PutByteConditionalFast(byte value, int length)
        {
            Data[Position] = value;

            Position += length;
        }

        /*

        public void Put(byte[] data, int offset, int length)
        {
            Buffer.Bl

            Buffer.BlockCopy(data, offset, data, position, length);
            position += length;
        }

        public void Put(byte[] data)
        {
            Buffer.BlockCopy(data, 0, data, position, data.Length);
            position += data.Length;
        }

        public void PutSBytesWithLength(sbyte[] data, int offset, int length)
        {
            FastBitConverter.GetBytes(this.data, position, length);
            Buffer.BlockCopy(data, offset, data, position + 4, length);
            position += length + 4;
        }

        public void PutSBytesWithLength(sbyte[] data)
        {
            FastBitConverter.GetBytes(this.data, position, data.Length);
            Buffer.BlockCopy(data, 0, data, position + 4, data.Length);
            position += data.Length + 4;
        }

        public void PutBytesWithLength(byte[] data, int offset, int length)
        {
            FastBitConverter.GetBytes(data, position, length);
            Buffer.BlockCopy(data, offset, data, position + 4, length);
            position += length + 4;
        }

        public void PutBytesWithLength(byte[] data)
        {
            FastBitConverter.GetBytes(this.data, position, data.Length);
            Buffer.BlockCopy(data, 0, this.data, position + 4, data.Length);
            position += data.Length + 4;
        }
        */

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Put(bool value)
        {
            Data[Position] = (byte)(value ? 1 : 0);

            Position++;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void PutArray(string[] value)
        {
            byte len = value == null ? (byte)0 : (byte)value.Length;

            Put(len);

            for (int i = 0; i < len; i++)
                Put(value[i]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void PutArray(string[] value, int maxLength)
        {
            ushort len = value == null ? (ushort)0 : (ushort)value.Length;

            Put(len);

            for (int i = 0; i < len; i++)
                Put(value[i], maxLength);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void PutArray(ushort[] value)
        {
            int len = value.Length;

            Put((ushort)len);

            for (int i = 0; i < len; i++)
                Put(value[i]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Memcpy(int srcOffset, ByteBuffer dest, int destOffset, int count)
        {
            Buffer.MemoryCopy(Data + srcOffset, dest.Data + destOffset, Connection.Mtu - destOffset, count);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Put(IPEndPoint endPoint)
        {
            Put(endPoint.Address.ToString());
            Put(endPoint.Port);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Put(string value)
        {
            Put(value, 80);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Put(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value))
            {
                Put((ushort)0);
                return;
            }

            int length = value.Length > maxLength ? maxLength : value.Length;
            //calculate max count
            int bytesCount;

            int byteCountPosition = Position;

            Position += 2;

#if UNITY_5_3_OR_NEWER
            fixed (char* str = value)
            {
                bytesCount = Encoding.UTF8.GetBytes(str, length, Data + Position, maxLength * 2);
            }
#else
            bytesCount = Encoding.UTF8.GetBytes(value.AsSpan(), new Span<byte>(Data + Position, maxLength * 2));
#endif

            *(ushort*)(Data + byteCountPosition) = (ushort)(bytesCount);

            Position += bytesCount;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public byte GetByte()
        {
            byte res = this.Data[this.Position];
            this.Position += 1;
            return res;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public float GetRotation()
        {
            return (GetByte() / 40.58448017647087f) - MathF.PI;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public sbyte GetSByte()
        {
            var b = (sbyte)this.Data[this.Position];
            this.Position++;
            return b;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool GetBool()
        {
            bool res = this.Data[this.Position] > 0;
            this.Position += 1;
            return res;
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void PutVarPositive(int value)
        {
            PutVar((uint)value);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void PutVar(int value)
        {
            uint zigzag = (uint)((value << 1) ^ (value >> 31));

            PutVar(zigzag);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void PutVar(uint value)
        {
            uint buffer;

            do
            {
                buffer = value & 0x7Fu;
                value >>= 7;

                if (value > 0)
                    buffer |= 0x80u;

                Put((byte)buffer);
            }

            while (value > 0);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public uint GetVarUInt()
        {
            uint buffer;
            uint value = 0x0u;
            int shift = 0;

            do
            {
                buffer = GetByte();

                value |= (buffer & 0x7Fu) << shift;
                shift += 7;
            }

            while ((buffer & 0x80u) > 0);

            return value;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public int GetVarInt()
        {
            uint value = GetVarUInt();

            int zagzig = (int)((value >> 1) ^ (-(int)(value & 1)));

            return zagzig;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public int GetVarIntPositive()
        {
            return (int)GetVarUInt();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ushort GetUShort()
        {
            ushort result;

            result = *(ushort*)(Data + Position);

            this.Position += 2;

            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public short GetShort()
        {
            short result = *(short*)(Data + Position);

            this.Position += 2;

            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public long GetLong()
        {
            long result = *(long*)(Data + Position);

            this.Position += 8;

            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ulong GetULong()
        {
            ulong result = *(ulong*)(Data + Position);

            Position += 8;

            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public int GetInt()
        {
            int result = *(int*)(Data + Position);

            this.Position += 4;

            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public uint GetUInt()
        {
            uint result = *(uint*)(Data + Position);

            this.Position += 4;

            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public float GetFloat()
        {
            return GetVarInt() * FloatDequantizeFactor;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public T Get<T>() where T: INetSerializable, new()
        {
            T instance = new T();

            instance.Read(this);

            return instance;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Put<T>(T instance) where T : INetSerializable, new()
        {
            instance.Write(this);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ushort[] GetUShortArray()
        {
            int len = GetUShort();

            ushort[] result = new ushort[len];

            for (int it = 0; it < len; ++it)
            {
                result[it] = GetUShort();
            }

            return result;
        }

        static unsafe void CustomCopy(void* dest, void* src, int count)
        {
            int block;

            block = count >> 3;

            long* pDest = (long*)dest;
            long* pSrc = (long*)src;

            for (int i = 0; i < block; i++)
            {
                *pDest = *pSrc; pDest++; pSrc++;
            }
            dest = pDest;
            src = pSrc;
            count = count - (block << 3);

            if (count > 0)
            {
                byte* pDestB = (byte*)dest;
                byte* pSrcB = (byte*)src;
                for (int i = 0; i < count; i++)
                {
                    *pDestB = *pSrcB; pDestB++; pSrcB++;
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe byte[] GetByteArray(int maxLength = 800)
        {
            int len = Math.Min((int)GetVarUInt(), 800);

            byte[] result = new byte[len];

            fixed (byte* src = result)
            {
                CustomCopy(src, (void*)(Data + Position), len);
            }

            Position += len;

            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public string GetStringFromByteArray()
        {
            int bytesCount = (int)GetVarUInt();

            if (bytesCount == 0)
                return "";

            string result;

            result = Encoding.UTF8.GetString(this.Data + this.Position, bytesCount);

            this.Position += bytesCount;

            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public string[] GetStringArray()
        {
            int len = GetByte();

            string[] result = new string[len];

            for (int it = 0; it < len; ++it)
            {
                result[it] = GetString();
            }

            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public string GetString()
        {
            return GetString(80);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public string GetString(int maxLength)
        {
            int bytesCount = GetUShort();

            if (bytesCount <= 0 || bytesCount > maxLength * 2)
            {
                return string.Empty;
            }

            string result;

            result = Encoding.UTF8.GetString(Data + this.Position, bytesCount);

            this.Position += bytesCount;

            return result;
        }

        public void PutSymbol(string symbol, int maxLength = 80)
        {
            if (string.IsNullOrEmpty(symbol))
            {
                PutVar((uint)0);
            }
            else
            {
                if (Connection.SymbolToIndex.TryGetValue(symbol, out uint index))
                {
                    PutVar(index);
                }
                else
                {
                    index = ++Connection.SymbolPool;

                    Connection.SymbolToIndex.Add(symbol, index);
                    Connection.IndexToSymbol.SetAt((int)index, symbol);

                    PutVar(index);
                    Put(symbol, maxLength);
                }
            }
        }

        public string GetSymbol(int maxLength = 80)
        {
            uint index = GetVarUInt(); // VAR 128 ENCODED FROM 1 TO 4 BYTES 

            if (index == 0)
            {
                return "";
            }
            else
            {
                String symbol;

                if (Connection.IndexToSymbolRemote.Size > index && (symbol = Connection.IndexToSymbolRemote.Values[index]) != null)
                {
                    return symbol;
                }
                else
                {
                    symbol = GetString(maxLength);

                    Connection.IndexToSymbolRemote.SetAt((int)index, symbol);
                    Connection.SymbolToIndexRemote.Add(symbol, index);

                    return symbol;
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ServerPacketType GetServerPacketType()
        {
            byte packetType = GetByte();
            return (ServerPacketType)packetType;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Put(ServerPacketType type)
        {
            Put((byte)type);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ClientPacketType GetClientPacketType()
        {
            return (ClientPacketType)GetByte();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Put(ClientPacketType type)
        {
            Put((byte)type);
        }

        public CraftingType GetCraftingType()
        {
            uint index = GetByte();

            if (index == 0)
            {
                return CraftingType.Undefined;
            }
            else
            {
                return (CraftingType)index;
            }
        }

        public void Put(CreatureVisual v)
        {
            switch (v)
            {
                case PrefabVisual pv:
                    PutVar((uint)(pv.Index + 1));
                    break;

                case HumanoidVisual hv:
                    {
                        PutVar((uint)0);

                        if (hv.Gender == 1)
                        {
                            Put((byte)(hv.Body + 128));
                        }
                        else
                        {
                            Put(hv.Body);
                        }

                        Put(hv.Race);
                        Put(hv.Robe);

                        if (hv.Robe > 0)
                        {
                            Put(hv.Boots);
                            Put(hv.Gloves);
                            Put(hv.Helmet);
                            PutVar(hv.Mount);
                            PutVar(hv.Weapon);
                            PutVar(hv.Offhand);
                            Put(hv.Cloak);
                        }
                        else
                        {
                            Put(hv.Beard);
                            Put(hv.Eye);
                            Put(hv.Eyebrow);
                            Put(hv.Hair);
                            Put(hv.Helmet);
                            Put(hv.Chest);
                            Put(hv.Boots);
                            Put(hv.Gloves);
                            Put(hv.Pants);
                            PutVar(hv.Mount);
                            PutVar(hv.Weapon);
                            PutVar(hv.Offhand);
                            Put(hv.Cloak);
                        }

                    }
                    break;
            }
        }

        public CreatureVisual GetCreatureVisual()
        {
            uint index = GetVarUInt();

            if (index == 0)
            {
                HumanoidVisual hv = new HumanoidVisual();

                hv.Body = GetByte();

                if (hv.Body >= 128)
                {
                    hv.Body = (byte)(hv.Body - 128);
                    hv.Gender = 1;
                }

                hv.Race = GetByte();
                hv.Robe = GetByte();

                if (hv.Robe > 0)
                {
                    hv.Boots = GetByte();
                    hv.Gloves = GetByte();
                    hv.Helmet = GetByte();
                    hv.Mount = GetVarUInt();
                    hv.Weapon = GetVarUInt();
                    hv.Offhand = GetVarUInt();
                    hv.Cloak = GetByte();
                }
                else
                {
                    hv.Beard = GetByte();
                    hv.Eye = GetByte();
                    hv.Eyebrow = GetByte();
                    hv.Hair = GetByte();
                    hv.Helmet = GetByte();
                    hv.Chest = GetByte();
                    hv.Boots = GetByte();
                    hv.Gloves = GetByte();
                    hv.Pants = GetByte();
                    hv.Mount = GetVarUInt();
                    hv.Weapon = GetVarUInt();
                    hv.Offhand = GetVarUInt();
                    hv.Cloak = GetByte();
                }

                return hv;
            }

            return new PrefabVisual() { Index = (int)(index - 1) };
        }

        public Item GetItem()
        {
            Item item;

            switch ((ItemClass)GetByte())
            {
                case ItemClass.None: return null;
                case ItemClass.Weapon: item = new Weapon(); break;
                case ItemClass.Chest: item = new Chest(); break;
                case ItemClass.Helmet: item = new Helmet(); break;
                case ItemClass.Gloves: item = new Gloves(); break;
                case ItemClass.Pants: item = new Pants(); break;
                case ItemClass.Boots: item = new Boots(); break;
                case ItemClass.Cloak: item = new Cloak(); break;
                case ItemClass.Shield: item = new Shield(); break;
                case ItemClass.Mount: item = new Mount(); break;
                case ItemClass.Ring: item = new Ring(); break;
                case ItemClass.Blueprint: item = new Blueprint(); break;
                case ItemClass.Necklace: item = new Necklace(); break;
                case ItemClass.Consumable: item = new Consumable(); break;
                case ItemClass.Resource: item = new Resource(); break;
                case ItemClass.Artifact: item = new Artifact(); break;
                case ItemClass.Head: item = new Head(); break;
                case ItemClass.Pet: item = new Pet(); break;
                case ItemClass.Robe: item = new Robe(); break;
                case ItemClass.Tool: item = new Tool(); break;
                default: throw new NotSupportedException();
            }

            item.Read(this);

            return item;
        }

        public void Put(Item item)
        {
            if (item == null)
                Put((byte)ItemClass.None);
            else
            {
                Put((byte)item.Class);
                item.Write(this);
            }
        }
    }
}