// src/store/authSlice.js
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import axios from 'axios';

// --- helpers ---
const normalizePerms = (arr) =>
  (Array.isArray(arr) ? arr : [])
    .map((p) => (typeof p === 'string' ? p.trim().toLowerCase() : ''))
    .filter(Boolean);

// استرجاع من التخزين مع تطبيع الصلاحيات
const tokenFromStorage = localStorage.getItem('token');
const userFromStorageRaw = localStorage.getItem('user');
let userFromStorage = userFromStorageRaw ? JSON.parse(userFromStorageRaw) : null;
if (userFromStorage?.permissions) {
  userFromStorage = { ...userFromStorage, permissions: normalizePerms(userFromStorage.permissions) };
}

const initialState = {
  token: tokenFromStorage || null,
  user: userFromStorage, // توقع: { id/_id, email, permissions: [] }
};

// نستخدم axios عاريًا (بدون apiClient) لتفادي circular dependency
// يجب الإبقاء على withCredentials لإرسال refresh cookie
const API_BASE_URL = 'http://localhost:8001/api';
// const API_BASE_URL = 'https://dash-board.senior.com.tr/api';

// Thunk لتسجيل الخروج: يخبر الباك إند أولاً ثم يمسح الحالة محليًا
export const logoutAsync = createAsyncThunk(
  'auth/logoutAsync',
  async (_, { dispatch }) => {
    try {
      await axios.post(`${API_BASE_URL}/auth/logout`, {}, { withCredentials: true });
    } catch (e) {
      // نتجاهل أي خطأ هنا (مثلاً انقطاع الشبكة) — المهم تنظيف الفرونت
    } finally {
      dispatch(authSlice.actions.logout());
    }
  }
);

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    // أكشن موحّد للتعامل مع استجابة تسجيل الدخول من الباك إند
    // payload = { token, user, permissions }
    setAuthFromLogin(state, action) {
      const { token, user, permissions } = action.payload || {};
      const perms = normalizePerms(permissions || user?.permissions);

      state.token = token || null;
      if (token) localStorage.setItem('token', token);
      else localStorage.removeItem('token');

      state.user = user ? { ...user, permissions: perms } : null;
      if (state.user) localStorage.setItem('user', JSON.stringify(state.user));
      else localStorage.removeItem('user');
    },

    setToken(state, action) {
      state.token = action.payload || null;
      if (action.payload) localStorage.setItem('token', action.payload);
      else localStorage.removeItem('token');
    },

    setUser(state, action) {
      const u = action.payload || null;
      // طبّع الصلاحيات لو موجودة داخل user
      const uNorm = u?.permissions ? { ...u, permissions: normalizePerms(u.permissions) } : u;
      state.user = uNorm;
      if (uNorm) localStorage.setItem('user', JSON.stringify(uNorm));
      else localStorage.removeItem('user');
    },

    setPermissions(state, action) {
      if (!state.user) state.user = {};
      state.user.permissions = normalizePerms(action.payload);
      localStorage.setItem('user', JSON.stringify(state.user));
    },

    logout(state) {
      state.token = null;
      state.user = null;
      localStorage.removeItem('token');
      localStorage.removeItem('user');
    },
  },
});

export const { setAuthFromLogin, setToken, setUser, setPermissions, logout } = authSlice.actions;

// Selectors
export const selectToken = (state) => state.auth.token;
export const selectUser = (state) => state.auth.user;

export default authSlice.reducer;
