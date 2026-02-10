import '../css/home.css';
import { useNavigate } from 'react-router-dom';

export const Home = () => {
    const navigate = useNavigate();

    return (
        <div className="home">
            <h1>Home Page</h1>
            <button onClick={() => navigate('/auth')}>Get Started</button>
        </div>
    )
}