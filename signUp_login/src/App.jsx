import { Home } from './pages/Home';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Auth } from './pages/Auth'; // Import the merged component
import { Nav } from './pages/Nav';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/auth" element={<Auth />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App