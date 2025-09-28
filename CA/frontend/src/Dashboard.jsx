import { useEffect, useState } from "react";
import axios from "axios";

export default function Dashboard() {
  const [csrs, setCsrs] = useState([]);
  const [signedCsrs, setSignedCsrs] = useState([]);
  const [refusedCsrs, setRefusedCsrs] = useState([]);
  const [revokedCsrs, setRevokedCsrs] = useState([]);
  const [error, setError] = useState(null);
  const [message, setMessage] = useState(null);

  useEffect(() => {
    axios
      .get("https://localhost:8100/pending-csrs")
      .then((res) => setCsrs(res.data))
      .catch(() => setError("Failed to load pending CSR data."));

    axios
      .get("https://localhost:8100/signed-pem")
      .then((res) => setSignedCsrs(res.data.map(email => ({ contact: email }))))
      .catch(() => setError("Failed to load signed CSR data."));

    axios
      .get("https://localhost:8100/refused-csrs")
      .then((res) => setRefusedCsrs(res.data.map(email => ({ contact: email }))))
      .catch(() => setError("Failed to load refused CSR data."));

    axios
      .get("https://localhost:8100/revoked-pem")
      .then((res) => setRevokedCsrs(res.data.map(email => ({ contact: email }))))
      .catch(() => setError("Failed to load revoked CSR data."));
  }, []);

  const handleSign = (email) => {
    const formData = new FormData();
    formData.append("email", email);

    axios
      .post("https://localhost:8100/sign-csr", formData)
      .then(() => {
        setMessage(`CSR for ${email} signed successfully.`);
        setCsrs(csrs.filter((csr) => csr.contact !== email));
        setSignedCsrs([...signedCsrs, { contact: email }]);
      })
      .catch((err) => {
        setMessage(`Error signing CSR for ${email}: ${JSON.stringify(err.response?.data || err)}`);
      });
  };

  const handleRefuse = (email) => {
    axios
      .delete("https://localhost:8100/refused", { params: { email } })
      .then(() => {
        setMessage(`CSR for ${email} refused successfully.`);
        setCsrs(csrs.filter((csr) => csr.contact !== email));
        setRefusedCsrs([...refusedCsrs, { contact: email }]);
      })
      .catch((err) => {
        setMessage(`Error refusing CSR for ${email}: ${JSON.stringify(err.response?.data || err)}`);
      });
  };

  const handleRevoke = (email) => {
    axios
      .delete("https://localhost:8100/revoke-signed", { params: { email } })
      .then(() => {
        setMessage(`CSR for ${email} revoked successfully.`);
        setSignedCsrs(signedCsrs.filter((csr) => csr.contact !== email));
        setRevokedCsrs([...revokedCsrs, { contact: email }]);
      })
      .catch((err) => {
        setMessage(`Error revoking CSR for ${email}: ${JSON.stringify(err.response?.data || err)}`);
      });
  };

  return (
    <div>
      <h2>Certificats en attente</h2>
      {error && <p>{error}</p>}
      {message && <p>{message}</p>}
      <ul>
        {csrs.length > 0 ? (
          csrs.map((csr, index) => (
            <li key={index}>
              <strong>Contact: {csr.contact} / Données: {JSON.stringify(csr.subject)}</strong><br />
              <button onClick={() => handleSign(csr.contact)}>✓ Sign</button>
              <button onClick={() => handleRefuse(csr.contact)}>X Refuse</button>
            </li>
          ))
        ) : (
          <p>Aucun CSR en attente</p>
        )}
      </ul>

      <h2>Certificats Signés</h2>
      <ul>
        {signedCsrs.length > 0 ? (
          signedCsrs.map((csr, index) => (
            <li key={index}>
              <strong>Contact: {csr.contact}</strong><br />
              <button onClick={() => handleRevoke(csr.contact)}>X Revoke</button>
            </li>
          ))
        ) : (
          <p>Aucun certificat signé</p>
        )}
      </ul>

      <h2>Certificats Refusés</h2>
      <ul>
        {refusedCsrs.length > 0 ? (
          refusedCsrs.map((csr, index) => (
            <li key={index}>
              <strong>Contact: {csr.contact}</strong><br />
            </li>
          ))
        ) : (
          <p>Aucun certificat refusé</p>
        )}
      </ul>

      <h2>Certificats Révoqués</h2>
      <ul>
        {revokedCsrs.length > 0 ? (
          revokedCsrs.map((csr, index) => (
            <li key={index}>
              <strong>Contact: {csr.contact}</strong><br />
            </li>
          ))
        ) : (
          <p>Aucun certificat révoqué</p>
        )}
      </ul>
    </div>
  );
}
