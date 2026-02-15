import { useNavigate } from "react-router-dom";

export const Dashboard = ()=>{
    const navigate = useNavigate();
    return(
        <div className="dashboard">
            <div className="home-nav" >
                <button onClick={()=>navigate('/')}>Go to Home</button>
            </div>
            <h1>This is dashboard page</h1>
        </div>
    )
}