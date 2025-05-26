// src/api/axiosInstance.js
import axios from 'axios';
import { toast } from 'react-toastify';
import { API_BASE_URL } from '../config/config';

const axiosInstance = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true,
});

let authUpdateToken = null;

export const setAuthUpdateToken = (callback) => {
  authUpdateToken = callback;
};

// Add a request interceptor to attach the token
axiosInstance.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('accessToken');
    // Check for token and that it's not the literal string "null"
    if (token && token !== 'null') {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  }
);

// Define paths where automatic redirect to /login should be suppressed
const NO_REDIRECT_ON_REFRESH_FAILURE_PATHS = ['/login', '/register'];

axiosInstance.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (
      error.response &&
      error.response.status === 401 &&
      !originalRequest._retry &&
      originalRequest.url !== '/auth/login' &&
      originalRequest.url !== '/auth/refresh'
    ) {
      originalRequest._retry = true;

      const hasAccessToken = localStorage.getItem('accessToken');

      if (hasAccessToken) {
        try {
          const refreshApiResponse = await axiosInstance.post('/auth/refresh', {}, { withCredentials: true });
          const authorizationHeader = refreshApiResponse.headers['authorization'];

          if (authorizationHeader) {
            const tokenValue = authorizationHeader.startsWith('Bearer ')
              ? authorizationHeader.split(' ')[1]
              : authorizationHeader;

            localStorage.setItem('accessToken', tokenValue);
            axiosInstance.defaults.headers.common['Authorization'] = `Bearer ${tokenValue}`;
            originalRequest.headers['Authorization'] = `Bearer ${tokenValue}`;

            //  Call authUpdateToken to update AuthContext state
            if (authUpdateToken) {
              authUpdateToken(tokenValue); // Notify AuthContext about the new token
            }


            return axiosInstance(originalRequest);
          } else {
            toast.error('Session update failed (no new token received). Please log in again.');
            localStorage.removeItem('accessToken');
            delete axiosInstance.defaults.headers.common['Authorization'];

            // HIGHLIGHTED CHANGE START: Call authUpdateToken to clear AuthContext state
            if (authUpdateToken) {
                authUpdateToken(null); // Notify AuthContext that the token is gone
            }
            // HIGHLIGHTED CHANGE END

            if (!NO_REDIRECT_ON_REFRESH_FAILURE_PATHS.includes(window.location.pathname)) {
              window.location.href = '/login';
            }
            return Promise.reject(new Error('Token refresh successful but no new token received.'));
          }
        } catch (refreshError) {
          let apiErrorMessage;

          if (refreshError.response && refreshError.response.data) {
            if (typeof refreshError.response.data === 'string' && refreshError.response.data.trim() !== '') {
              apiErrorMessage = refreshError.response.data;
            } else if (refreshError.response.data.message && typeof refreshError.response.data.message === 'string' && refreshError.response.data.message.trim() !== '') {
              apiErrorMessage = refreshError.response.data.message;
            } else if (refreshError.response.data.error && typeof refreshError.response.data.error === 'string' && refreshError.response.data.error.trim() !== '') {
              apiErrorMessage = refreshError.response.data.error;
            }
          }

          const displayMessage = apiErrorMessage || 'Your session has expired. Please log in again.';
          toast.error(displayMessage);

          localStorage.removeItem('accessToken');
          delete axiosInstance.defaults.headers.common['Authorization'];

          // HIGHLIGHTED CHANGE START: Call authUpdateToken to clear AuthContext state
          if (authUpdateToken) {
              authUpdateToken(null); // Notify AuthContext that the token is gone
          }
          // HIGHLIGHTED CHANGE END

          if (!NO_REDIRECT_ON_REFRESH_FAILURE_PATHS.includes(window.location.pathname)) {
            window.location.href = '/login';
          }
          return Promise.reject(refreshError);
        }
      } else {
        return Promise.reject(error);
      }
    }

    return Promise.reject(error);
  }
);

export default axiosInstance;