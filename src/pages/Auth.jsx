import { useNavigate } from "react-router-dom"
import { useState } from "react"
import { useAuth } from "../context/AuthContext"

export const Auth = ()=>{
    
    const navigate = useNavigate();
    const [isLogin, setIsLogin] = useState(true);
    const [formData, setFormData] = useState({
        username:"",
        email:"",
        password:"",
        confirmPassword:""
    })

    const [error, setError] = useState({});
    const { login } = useAuth();

    const handleSubmit = (e)=>{
        e.preventDefault();
        const newError = validateForm();
        if(Object.keys(newError).length > 0){
            setError(newError);
            return;
        }
        // login(formData.username || formData.email.split('@')[0], formData.email);
        navigate('/dashboard');
        
    }
    

    const handleChange = (e)=>{
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });

        if(error[e.target.name]){
        setError({
            ...error,
            [e.target.name]: ''
        })
    }
    }

    function validateForm(){
        const newError = {};

        if(!formData.email){
            newError.email = "Email is required";
        } else if(!/\S+@\S+\.\S+/.test(formData.email)){
            newError.email = "Email is invalid";
        }

        if(!formData.password){
            newError.password = "Password is required";
        } else if(formData.password.length < 6){
            newError.password = "Password must of length 6 or more ";
        }

        if(!isLogin){
            if(!formData.username.trim()){
                newError.username = "Username is required";
            } 
        if (!formData.confirmPassword) {
            newError.confirmPassword = 'Please confirm your password';
        } else if (formData.password !== formData.confirmPassword) {
            newError.confirmPassword = 'Passwords do not match';
      }
    }

        return newError;
    }

    function toggleMode(){
        setIsLogin(!isLogin);
        setFormData({
            username:"",
            email:"",
            password:"",
            confirmPassword:""
        });
        setError({
        })
    }
    return(
        <div className="auth-check">
             <div className="home-nav" >
                <button onClick={()=>navigate('/')}>Go to Home</button>
            </div>
            <h1>This is auth page</h1>
            <h3>{isLogin? "Login": "SignUP"}</h3>
            <form action="" className="auth-class" onSubmit={handleSubmit}>
                  {!isLogin && (
            <div className="form-group">
              <input
                type="text"
                name="username"
                placeholder="Username"
                value={formData.username}
                onChange={handleChange}
                className={error.username ? 'error' : ''}
              />
              {error.username && <span className="error-message">{error.username}</span>}
            </div>
          )}

               <div className="form-group">
            <input
              type="email"
              name="email"
              placeholder="Email"
              value={formData.email}
              onChange={handleChange}
              className={error.email ? 'error' : ''}
            />
            {error.email && <span className="error-message">{error.email}</span>}
          </div>
                
             <div className="form-group">
            <input
              type="password"
              name="password"
              placeholder="Password"
              value={formData.password}
              onChange={handleChange}
              className={error.password ? 'error' : ''}
            />
            {error.password && <span className="error-message">{error.password}</span>}
          </div>
               {!isLogin && (
            <div className="form-group">
              <input
                type="password"
                name="confirmPassword"
                placeholder="Confirm Password"
                value={formData.confirmPassword}
                onChange={handleChange}
                className={error.confirmPassword ? 'error' : ''}
              />
              {error.confirmPassword && (
                <span className="error-message">{error.confirmPassword}</span>
              )}
            </div>
          )}

                <button type="submit">{isLogin? "Login": "SignUP"}</button>
                
            </form>
            <p className="toggle-text">
          {isLogin ? "Don't have an account? " : 'Already have an account? '}
          <span onClick={toggleMode} className="toggle-link">
            {isLogin ? 'Sign Up' : 'Login'}
          </span>
        </p>
        </div>
    )
}