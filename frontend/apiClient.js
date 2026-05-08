// src/services/apiClient.js
import axios from "axios";
import { store } from "../store";
import { setToken, logout } from "../store/authSlice";
import normalizeApiError from "./extractApiError";

const api = axios.create({
    baseURL: "http://localhost:8001/api",
    //baseURL: "https://dash-board.senior.com.tr/api",
    withCredentials: true, // مهم: لإرسال httpOnly refresh cookie
});

// طلبات: إرفاق التوكن + Accept-Language من i18n لو أردت
api.interceptors.request.use((config) => {
    try {
        const state = store.getState();
        const token = state.auth?.token || localStorage.getItem("token");
        if (token) config.headers.Authorization = `Bearer ${token}`;
    } catch {}
    // const lang = localStorage.getItem('i18nextLng') || 'ar';
    // config.headers['Accept-Language'] = lang;
    return config;
});

// Auto refresh logic -
let isRefreshing = false;
let refreshQueue = [];

const processQueue = (error, token = null) => {
    refreshQueue.forEach(({ resolve, reject }) => {
        if (error) reject(error);
        else resolve(token);
    });
    refreshQueue = [];
};

const isAuthEndpoint = (url = "") =>
    url.includes("/auth/refresh") ||
    url.includes("/auth/login") ||
    url.includes("/auth/logout");

api.interceptors.response.use(
    (res) => res,
    async (error) => {
        const original = error.config;
        const status = error.response?.status;
        const url = original?.url || "";

        // 401
        if (status === 401 && original && !original._retry && !isAuthEndpoint(url)) {
            if (isRefreshing) {
                // Queue
                return new Promise((resolve, reject) => {
                    refreshQueue.push({ resolve, reject });
                })
                .then((newToken) => {
                        original.headers.Authorization = `Bearer ${newToken}`;
                        return api(original);
                })
                .catch((err) => Promise.reject(err));
            }

            original._retry = true;
            isRefreshing = true;

            try {
                const { data } = await api.post("/auth/refresh");
                const newToken = data?.token;
                if (!newToken) throw new Error("No token returned from refresh");
              
                store.dispatch(setToken(newToken));
                processQueue(null, newToken);
              
                original.headers.Authorization = `Bearer ${newToken}`;
                return api(original);
            } catch (refreshError) {
                processQueue(refreshError, null);
                store.dispatch(logout());
                return Promise.reject(refreshError);
            } finally {
                isRefreshing = false;
            }
        }

        // 401 
        const normalized = normalizeApiError(error);
        if (normalized.status === 401 && isAuthEndpoint(url) && !url.includes("/auth/login")) {
            store.dispatch(logout());
        }

        return Promise.reject(error);
    }
);

export default api;
