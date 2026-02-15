import { useNavigate } from "react-router-dom";


export const Home = ()=>{
    const navigate = useNavigate();

    return(
        <div className="home">
            <div className="button-nav">
                <button onClick={()=>navigate('/auth')}>Login and Sign Up</button>
                <button onClick={()=>navigate('/dashboard')}>Go to Dashboard</button>
            </div>
            <h1>This is home page</h1>
            
        </div>
    )
}