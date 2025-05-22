import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { AuthProvider } from './context/AuthContext';
import { BrowserRouter } from 'react-router-dom';


const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <AuthProvider> {/* Wrap App with AuthProvider for auth context */}
      <BrowserRouter> {/* Wrap App with BrowserRouter for routing */}
        <App />
      </BrowserRouter>
    </AuthProvider>
  </React.StrictMode>
);
