import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
// import Login from './pages/Login'
import Dashboard from './Dashboard.jsx'

function App() {
  return (
    <Router basename="/Home">
      <Routes>
        <Route path="/" element={<Dashboard />} />
      </Routes>
    </Router>
  )
}

export default App
