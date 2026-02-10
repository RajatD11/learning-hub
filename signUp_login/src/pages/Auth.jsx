import { useState } from 'react';
import '../css/auth.css'; 
import { Nav } from './Nav';

export const Auth = () => {
    const [isLogin, setIsLogin] = useState(true); 
    
    const [form, setForm] = useState({
        username: '',
        email: '',
        password: ''
    });

    function handleChange(e) {
        setForm({
            ...form,
            [e.target.name]: e.target.value
        });
    }

    function handleSubmit(e) {
        e.preventDefault();
        
        if (isLogin) {
            console.log('Login data:', { email: form.email, password: form.password });
        } else {
            console.log('SignUp data:', form);
        }
    }

    function toggleMode() {
        setIsLogin(!isLogin);
        setForm({
            username: '',
            email: '',
            password: ''
        });
    }

    return (
        <div className="nav">
            <Nav />
        <div className='container'>
            <div className='login'>
                <div>
                    <h1>{isLogin ? 'Login' : 'Sign Up'}</h1>
                    <form onSubmit={handleSubmit}>
                        {!isLogin && (
                            <input
                                type="text"
                                name="username"
                                placeholder="Username"
                                onChange={handleChange}
                                value={form.username}
                                required
                            />
                        )}
                        <input
                            type="email"
                            name="email"
                            placeholder="Email"
                            onChange={handleChange}
                            value={form.email}
                            required
                        />
                        <input
                            type="password"
                            name="password"
                            placeholder="Password"
                            onChange={handleChange}
                            value={form.password}
                            required
                        />
                        
                        <button type="submit">
                            {isLogin ? 'Login' : 'Sign Up'}
                        </button>
                    </form>

                    <p className="toggle-text">
                        {isLogin ? "Don't have an account? " : "Already have an account? "}
                        <span onClick={toggleMode} className="toggle-link">
                            {isLogin ? 'Sign Up' : 'Login'}
                        </span>
                    </p>
                </div>
            </div>
        </div>
        </div>
    );
};