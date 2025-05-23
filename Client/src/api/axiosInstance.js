// src/api/axiosInstance.js
import axios from 'axios';
import { toast } from 'react-toastify';
import { API_BASE_URL } from '../config/config';

const axiosInstance = axios.create({
  baseURL: API_BASE_URL,
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

    // Check for 401 Unauthorized, ensure it's not already retried,
    // and that it's not a login or refresh request itself.
    if (
      error.response &&
      error.response.status === 401 &&
      !originalRequest._retry &&
      originalRequest.url !== '/auth/login' && // Prevent infinite loop for login failures
      originalRequest.url !== '/auth/refresh' // Prevent infinite loop for refresh failures
    ) {
      originalRequest._retry = true; // Mark request as retried

      // ONLY attempt refresh if an accessToken exists in localStorage.
      // This implies a user was previously logged in.
      const hasAccessToken = localStorage.getItem('accessToken');

      if (hasAccessToken) {
        try {
          const refreshApiResponse = await axiosInstance.post('/auth/refresh', {}, { withCredentials: true });
          const authorizationHeader = refreshApiResponse.headers['authorization'];

          if (authorizationHeader) {
            const tokenValue = authorizationHeader.startsWith('Bearer ')
              ? authorizationHeader.split(' ')[1]
              : authorizationHeader;

            localStorage.setItem('accessToken', tokenValue); // Update local storage with new token
            axiosInstance.defaults.headers.common['Authorization'] = `Bearer ${tokenValue}`; // Update default header
            originalRequest.headers['Authorization'] = `Bearer ${tokenValue}`; // Update header for the original failed request

            // Retry the original request with the new token
            return axiosInstance(originalRequest);
          } else {
            // Refresh API responded successfully (e.g., 200 OK) but didn't provide a new token.
            // This indicates a successful refresh but an issue on the backend with token provision.
            toast.error('Session update failed (no new token received). Please log in again.');
            localStorage.removeItem('accessToken');
            delete axiosInstance.defaults.headers.common['Authorization'];

            if (!NO_REDIRECT_ON_REFRESH_FAILURE_PATHS.includes(window.location.pathname)) {
              window.location.href = '/login'; // Redirect to login
            }
            return Promise.reject(new Error('Token refresh successful but no new token received.'));
          }
        } catch (refreshError) {
          // Refresh token API call failed (e.g., refresh token expired, invalid, or network issue).
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

          // Use the extracted API error message or a default fallback message.
          const displayMessage = apiErrorMessage || 'Your session has expired. Please log in again.';
          toast.error(displayMessage);

          localStorage.removeItem('accessToken'); // Clear invalid token
          delete axiosInstance.defaults.headers.common['Authorization']; // Clear header

          if (!NO_REDIRECT_ON_REFRESH_FAILURE_PATHS.includes(window.location.pathname)) {
            window.location.href = '/login'; // Redirect to login
          }
          return Promise.reject(refreshError); // Reject the original error
        }
      } else {
        // If there's no accessToken in localStorage, it means the user is not authenticated
        // in a persistent session, so don't attempt a refresh. Just reject the original error.
        // This covers cases like registration or initial login attempts.
        return Promise.reject(error);
      }
    }

    // For any other error (not 401, already retried, or login/refresh request)
    return Promise.reject(error);
  }
);



export default axiosInstance;
