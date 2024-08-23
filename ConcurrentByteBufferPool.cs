namespace Server
{
    public class ConcurrentByteBufferPool
    {
        private static readonly ByteBufferPool global = new ByteBufferPool();

        [ThreadStatic]
        private static ByteBufferPool local;

        public static ByteBuffer Acquire()
        {
            ByteBuffer buffer = null;

            if (local == null)
            {
                buffer = TakeFromGlobal();
            }
            else
            {
                buffer = local.Take();

                if (buffer == null)
                    buffer = TakeFromGlobal();
            }

            return buffer ?? new ByteBuffer();
        }

        public static void Release(ByteBuffer buffer)
        {
            if (local == null)
                local = new ByteBufferPool();

            buffer.Reset();
            local.Add(buffer);
        }

        public static void Merge()
        {
            if (local != null && local.Length > 0)
                global.Merge(local);
        }

        public static ByteBuffer Clear()
        {
            return global.Clear();
        }

        private static ByteBuffer TakeFromGlobal()
        {
            return global.Take();
        }
    }  
}
