// 1. Import React tools
import React, { createContext, useState, useEffect } from 'react';

// 2. Create the context
export const AuthContext = createContext();

// 3. Create the context provider component
export const AuthProvider = ({ children }) => {
  // Keeps track of login status
  const [isAuthenticated, setIsAuthenticated] = useState(() => {
    return !!localStorage.getItem('accessToken');
  });
  // 4. Check if already logged in (on first load)
  useEffect(() => {
    const token = localStorage.getItem('accessToken');
    if (token) setIsAuthenticated(true);
  }, []);

  // 5. Login function
  const login = (token) => {
    // ✅ Strip 'Bearer ' before storing, store only the raw token
    const tokenValue = token.startsWith('Bearer ') ? token.split(' ')[1] : token;
    localStorage.setItem('accessToken', tokenValue);
    setIsAuthenticated(true);
  };

  // 6. Logout function
  const logout = () => {
    localStorage.removeItem('accessToken');
    setIsAuthenticated(false);
    
  };

  // 7. Provide these values to children
  return (
    <AuthContext.Provider value={{ isAuthenticated, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};
