namespace VEthernet.Hooking
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Reflection.Emit;

    public unsafe class Ptr<TValue>
    {
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly IDictionary<Type, object> pointers = new Dictionary<Type, object>();

        protected delegate void SafeGetPointer<TOut>(out TOut out_, long far);
        protected delegate void SafeSetPointer<TIn>(long far, TIn in_);

        private readonly SafeGetPointer<TValue> getp;
        private readonly SafeSetPointer<TValue> setp;

        public virtual TValue this[long far]
        {
            get
            {
                return this.GetValue(far);
            }
            set
            {
                this.SetValue(far, value);
            }
        }

        public virtual TValue GetValue(long far)
        {
            TValue value;
            this.getp(out value, far);
            return value;
        }

        public virtual void SetValue(long far, TValue value)
        {
            this.setp(far, value);
        }

        protected Ptr(SafeGetPointer<TValue> getp, SafeSetPointer<TValue> setp)
        {
            if (getp == null)
            {
                throw new ArgumentNullException("getp");
            }
            if (setp == null)
            {
                throw new ArgumentNullException("setp");
            }
            this.setp = setp;
            this.getp = getp;
        }

        public object Tag
        {
            get;
            set;
        }

        public static int GetChunkSize()
        {
            TValue[] s = new TValue[2];
            TypedReference r1 = __makeref(s[0]);
            TypedReference r2 = __makeref(s[1]);
            long p1 = (long)*(IntPtr**)&r1;
            long p2 = (long)*(IntPtr**)&r2;
            long sz = p2 - p1;
            return unchecked((int)sz);
        }

        public static long GetReferencePointer(ref TValue value)
        {
            return GetReferencePointer(__makeref(value));
        }

        public static long GetReferencePointer(TypedReference reference)
        {
            return (long)*(IntPtr**)&reference;
        }

        public static Ptr<TValue> GetPtr()
        {
            lock (pointers)
            {
                object o;
                if (pointers.TryGetValue(typeof(TValue), out o))
                {
                    return (Ptr<TValue>)o;
                }
                Ptr<TValue> pointer = new Ptr<TValue>(CreateGetPointer(), CreateSetPointer());
                pointers.Add(typeof(TValue), pointer);
                return pointer;
            }
        }

        private static SafeGetPointer<TValue> CreateGetPointer()
        {
            DynamicMethod dm = new DynamicMethod(string.Empty,
            typeof(void), new[]
            {
                    typeof(TValue).MakeByRefType(),
                    typeof(long),
            }, typeof(TValue).Module, true);
            ILGenerator il = dm.GetILGenerator();

            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldarg_1);
            il.Emit(OpCodes.Ldobj, typeof(TValue));
            il.Emit(OpCodes.Stobj, typeof(TValue));

            il.Emit(OpCodes.Ret);

            return (SafeGetPointer<TValue>)dm.CreateDelegate(typeof(SafeGetPointer<TValue>));
        }

        private static SafeSetPointer<TValue> CreateSetPointer()
        {
            DynamicMethod dm = new DynamicMethod(string.Empty, typeof(void),
            new Type[]
            {
                    typeof(long),
                    typeof(TValue),
            }, typeof(TValue).Module, true);
            ILGenerator il = dm.GetILGenerator();

            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldarg_1);
            il.Emit(OpCodes.Stobj, typeof(TValue));

            il.Emit(OpCodes.Ret);

            return (SafeSetPointer<TValue>)dm.CreateDelegate(typeof(SafeSetPointer<TValue>));
        }
    }
}
