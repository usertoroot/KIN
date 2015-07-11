using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace KIN
{
    public abstract class CSingleton<T> where T : class, new()
    {
        private static T m_singleton = null;
        public static T Singleton
        {
            get
            {
                if (m_singleton == null)
                    m_singleton = new T();
                return m_singleton;
            }
        }
    }
}
