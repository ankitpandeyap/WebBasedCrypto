// src/api/axiosInstance.js
import axios from 'axios';
import { toast } from 'react-toastify';


const axiosInstance = axios.create({
  baseURL: 'http://localhost:8082/api',
  withCredentials: true,
});

// Add a request interceptor to attach the token
axiosInstance.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('accessToken');
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;

    }
    return config;
  },
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('accessToken');
      window.location.href = '/login'; // Force logout
    }
    return Promise.reject(error);
  }

);

// Define paths where automatic redirect to /login should be suppressed
// if a token refresh attempt ultimately fails.
// Ensure these paths match your actual react-router-dom routes.
const NO_REDIRECT_ON_REFRESH_FAILURE_PATHS = ['/login', '/register'];
// If you have a separate route like '/verify-otp', add it to the list:
// const NO_REDIRECT_ON_REFRESH_FAILURE_PATHS = ['/login', '/register', '/verify-otp'];

axiosInstance.interceptors.response.use(
  (response) => response, // If successful, just return the response
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

          return axiosInstance(originalRequest);
        } else {
          // Refresh API responded with success (e.g., 200 OK) but no new token was in the header.
          // This is a client-side interpretation of an incomplete success, so a client-defined message is often best.
          toast.error('Session update failed (no new token received). Please log in again.');
          localStorage.removeItem('accessToken');
          delete axiosInstance.defaults.headers.common['Authorization'];

          if (!NO_REDIRECT_ON_REFRESH_FAILURE_PATHS.includes(window.location.pathname)) {
            window.location.href = '/login';
          }
          return Promise.reject(new Error('Token refresh successful but no new token received.'));
        }
      } catch (refreshError) {
        // Token refresh attempt failed (e.g., refresh token is invalid, expired, or a network error occurred)
        let apiErrorMessage;

        if (refreshError.response && refreshError.response.data) {
          // 1. If response.data is directly a non-empty string, use it.
          if (typeof refreshError.response.data === 'string' && refreshError.response.data.trim() !== '') {
            apiErrorMessage = refreshError.response.data;
          }
          // 2. Else, if response.data.message is a non-empty string.
          else if (refreshError.response.data.message && typeof refreshError.response.data.message === 'string' && refreshError.response.data.message.trim() !== '') {
            apiErrorMessage = refreshError.response.data.message;
          }
          // 3. Else, if response.data.error is a non-empty string (another common pattern).
          else if (refreshError.response.data.error && typeof refreshError.response.data.error === 'string' && refreshError.response.data.error.trim() !== '') {
            apiErrorMessage = refreshError.response.data.error;
          }
        }

        // Use the extracted API error message or a default fallback message.
        const displayMessage = apiErrorMessage || 'Your session has expired. Please log in again.';
        toast.error(displayMessage);

        localStorage.removeItem('accessToken');
        delete axiosInstance.defaults.headers.common['Authorization'];

        if (!NO_REDIRECT_ON_REFRESH_FAILURE_PATHS.includes(window.location.pathname)) {
          window.location.href = '/login';
        }
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);


export default axiosInstance;
