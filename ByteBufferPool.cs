using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Networking
{
    public static class ConcurrentByteBufferPool
    {
        static ByteBufferPool Global = new ByteBufferPool();

        [ThreadStatic]
        static ByteBufferPool Local;

        public static ByteBuffer Acquire()
        {
            ByteBuffer buffer;

            if (Local == null)
            {
                lock (Global)
                {
                    buffer = Global.Take();
                }
            }
            else
            {
                buffer = Local.Take();

                if (buffer == null)
                {
                    lock (Global)
                    {
                        buffer = Global.Take();
                    }
                }
            }

            if (buffer == null)
            {
                buffer = new ByteBuffer();
            }

            return buffer;
        }

        public static void Release(ByteBuffer buffer)
        {
            if (Local == null)
            {
                Local = new ByteBufferPool();
            }

            buffer.Reset();

            Local.Add(buffer);
        }

        public static void Merge()
        {
            if (Local != null && Local.Head != null)
            {
                lock (Global)
                {
                    Global.Merge(Local);
                }
            }
        }

        public static ByteBuffer Clear()
        {
            lock (Global)
            {
                return Global.Clear();
            }
        }
    }

    public class ByteBufferPool
    {
        public ByteBuffer Head;
        public ByteBuffer Tail;

        public static readonly ByteBufferPool Global = new ByteBufferPool();

        [ThreadStatic]
        public static ByteBufferPool Local;

        public void Add(ByteBuffer buffer)
        {
            buffer.Next = Head;

            if (Tail == null)
            {
                Tail = buffer;
            }

            Head = buffer;
        }

        public ByteBuffer Clear()
        {
            ByteBuffer result = Head;

            Head = null;
            Tail = null;

            return result;
        }

        public ByteBuffer Take()
        {
            if (Head == null)
            {
                return null;
            }
            else
            {
                ByteBuffer result = Head;

                if (Head == Tail)
                {
                    Head = null;
                    Tail = null;
                }
                else
                {
                    Head = Head.Next;
                }

                return result;
            }
        }

        public int Length
        {
            get
            {
                int val = 0;

                ByteBuffer current = Head;

                while(current != null)
                {
                    current = current.Next;

                    ++val;
                }

                return val;
            }
        }

        public void Merge(ByteBufferPool other)
        {
            if (Head == null)
            {
                Head = other.Head;
                Tail = other.Tail;
            }
            else
                if (other.Head != null)
            {
                Tail.Next = other.Head;

                Tail = other.Tail;
            }

            other.Head = null;
            other.Tail = null;
        }
    }
}
