import { useState } from "react";
import tourismVideo from "../assets/jogfalls.mp4";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");

  const handleLogin = async (e) => {
    e.preventDefault();

    try {
      const response = await fetch("http://localhost:8080/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email,
          password,
        }),
      });

      const data = await response.json();

      if (response.ok) {
        setMessage("Login successful ");
        localStorage.setItem("token", data.token);
      } else {
        setMessage(data.message);
      }
    } catch (error) {
      setMessage("Server error");
    }
  };

  return (
    <div className="min-h-screen flex bg-black">

      <div className="hidden lg:block lg:w-1/2 relative">
        <video autoPlay loop muted className="w-full h-full object-cover">
          <source src={tourismVideo} type="video/mp4" />
        </video>

        <div className="absolute inset-0 bg-black/40 flex items-center justify-center">
          <div className="text-center text-white px-10">
            <h1 className="text-6xl font-extrabold leading-tight drop-shadow-2xl">
              Explore Karnataka
            </h1>

            <p className="mt-6 text-2xl text-slate-200 font-light tracking-wide">
              Waterfalls. Heritage. Nature.
            </p>
          </div>
        </div>
      </div>

      <div className="w-full lg:w-1/2 flex items-center justify-center bg-gradient-to-br from-blue-950 via-slate-900 to-cyan-900 p-4">
        <div className="w-full max-w-md bg-white/10 backdrop-blur-lg border border-white/20 rounded-3xl shadow-2xl p-8">
          <div className="text-center mb-8">
            <h1 className="text-4xl font-bold text-white mb-2">Tourism App</h1>

            <p className="text-slate-300">Explore the Karnataka with us  🌄</p>
          </div>

          <form onSubmit={handleLogin} className="space-y-5">
            <div>
              <label className="text-white block mb-2">Email</label>

              <input
                type="email"
                placeholder="Enter your email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-4 py-3 rounded-xl bg-white/20 text-white outline-none border border-white/20 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400"
                required
              />
            </div>

            <div>
              <label className="text-white block mb-2">Password</label>

              <input
                type="password"
                placeholder="Enter password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-3 rounded-xl bg-white/20 text-white outline-none border border-white/20 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400"
                required
              />
            </div>

            <button
              type="submit"
              className="w-full bg-cyan-500 hover:bg-cyan-400 transition-all duration-300 text-white font-bold py-3 rounded-xl"
            >
              Login
            </button>
          </form>

          {message && (
            <p className="text-center mt-5 text-white font-medium">{message}</p>
          )}

          <p className="text-center text-slate-300 mt-6 text-sm">
            Don’t have an account? Register
          </p>
        </div>
      </div>
    </div>
  );
}
