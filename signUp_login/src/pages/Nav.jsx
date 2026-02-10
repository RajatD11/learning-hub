import { useNavigate } from "react-router-dom";

export const Nav = () =>{
    const navi = useNavigate();
    function HomeMove(){
        navi('/');
    }
    return(
        <div className="nav">
            <button onClick={HomeMove}>Home</button>
        </div>
       
    )
}