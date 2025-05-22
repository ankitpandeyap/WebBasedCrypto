import { Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Register from './pages/Register';
import ProtectedRoute from './components/ProtectedRoute';
import { useLocation } from 'react-router-dom';
import Footer from './components/Footer';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import './App.css'
import ComposeMessage from './pages/ComposeMessage';

export default function App() {
  const location = useLocation(); // 🔍 Detect current route

  return (
    <>
   
    <Routes>
      <Route path="/" element={<Navigate to="/login" />} />
      <Route path="/register" element={<Register />} />
      <Route path="/login" element={<Login />} />
      <Route path="/dashboard" element={<Dashboard />} />
       <Route path="/compose" element={<ComposeMessage />} />
     
      {/* <Route
        path="/dashboard"
        element={
          <ProtectedRoute>
            <Dashboard />
          </ProtectedRoute>
        }
      /> */}
      {/* <Route
        path="/compose"
        element={
          <ProtectedRoute>
            <ComposeMessage />
          </ProtectedRoute>
        }
      /> */}
    </Routes>
   {location.pathname === '/login' && <Footer />}
   <ToastContainer position="top-center" autoClose={1000} />
   </>
  );
}
