import React, { useState, useEffect } from "react";
import forge from "node-forge";

interface TrustedFormProps {
  email: string;
}

const TrustedForm: React.FC<TrustedFormProps> = ({ email }) => {
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const [fields, setFields] = useState({
    firstname: "",
    lastname: "",
    organisation: "",
    country: "",
    state: "",
  });

  useEffect(() => {
    if (isSubmitted) {
      alert("Inscription réussie ! Vous pouvez maintenant vous connecter.");
      window.location.href = "/Login";
    }
  }, [isSubmitted]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFields((prev) => ({ ...prev, [name]: value }));
  };

  const handleGenerate = async () => {
    if (isSubmitted || isLoading) return;

    setIsLoading(true);

    try {
      const { firstname, lastname, organisation, country, state } = fields;

      const pki = forge.pki;
      const keypair = pki.rsa.generateKeyPair(2048);

      const csr = pki.createCertificationRequest();
      csr.publicKey = keypair.publicKey;
      // eslint-disable-next-line no-control-regex
      console.log("email ascii ?", /^[\x00-\x7F]*$/.test(email));
      csr.setSubject([
        { name: "commonName", value: `${firstname} ${lastname}` },
        { name: "organizationName", value: organisation },
        { name: "countryName", value: country },
        { name: "stateOrProvinceName", value: state },
        {
          type: "1.2.840.113549.1.9.1",
          value: email,
          // @ts-ignore
          valueTagClass: forge.asn1.Type.IA5STRING
        }
      ]);
      csr.sign(keypair.privateKey);

      const csrPem = pki.certificationRequestToPem(csr);
      const privateKeyPem = pki.privateKeyToPem(keypair.privateKey);

      // Téléchargement clé privée
      const blob = new Blob([privateKeyPem], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${email}.key`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      // Envoi du CSR
      const file = new File([csrPem], `${email}.csr`, { type: "text/plain" });
      const formData = new FormData();
      formData.append("file", file);

      const response = await fetch("https://localhost:8100/submit-csr", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error("Erreur lors de l’envoi du CSR.");
      }

      setIsSubmitted(true);
    } catch (err) {
      console.error("Échec de l’envoi :", err);
      alert("Erreur lors de l’envoi du CSR.");
      setIsLoading(false);
    }
  };

  if (isSubmitted) {
    return <p>Vous avez déjà fait une demande de CSR. Merci de patienter.</p>;
  }

  return (
    <div className="trusted-form">
      <input
        name="firstname"
        placeholder="Prénom"
        value={fields.firstname}
        onChange={handleChange}
        required
      />
      <input
        name="lastname"
        placeholder="Nom"
        value={fields.lastname}
        onChange={handleChange}
        required
      />
      <input
        name="organisation"
        placeholder="Organisation"
        value={fields.organisation}
        onChange={handleChange}
        required
      />
      <input
        name="country"
        placeholder="Pays"
        value={fields.country}
        onChange={handleChange}
        required
      />
      <input
        name="state"
        placeholder="Région/État"
        value={fields.state}
        onChange={handleChange}
        required
      />
      <button onClick={handleGenerate} disabled={isLoading}>
        {isLoading ? "Patientez..." : "Générer clé & CSR"}
      </button>
    </div>
  );
};

export default TrustedForm;
