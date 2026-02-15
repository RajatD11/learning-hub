import { useContext, useEffect, useState, createContext } from "react";

const AuthContext = createContext();

export const AuthProvider = ({children})=>{
    const [user, setUser] = useState(null);

    useEffect(()=>{
        const stored = localStorage.getItem('user');
        if(stored){
            setUser(JSON.parse(stored));
        }
    },[])

    const Login =(username, email)=>{
        const userData = {username,email};
        setUser(userData);
        localStorage.setItem('user',JSON.stringify(userData));
    }

    const Logout = ()=>{
        setUser(null);
        localStorage.removeItem('user')
    }

    const isAuthenticated = !!user;

    const value = {
        user,
        Login,
        Logout,
        isAuthenticated
    }

    return(
        <AuthContext.Provider value = {value}>{children}</AuthContext.Provider>
    )

    }
export function useAuth() {
    const context = useContext(AuthContext);

    if (!context) {
        throw new Error("useAuth must be used within an AuthProvider");
    }

    return context;
}