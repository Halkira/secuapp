import React, { useState, useEffect } from "react";
import { Video } from "../components/Video";
import sessionManager from "../../components/sessionManager.tsx";

interface StreamFile {
    filename: string;
    size_bytes: number;
    size_human: string;
    creation_date: string;
}

interface StreamData {
    [streamId: string]: StreamFile[];
}

interface ApiResponse {
    streams: StreamData;
}

const Home: React.FC = () => {
    const [streamData, setStreamData] = useState<ApiResponse | null>(null);

    // Utiliser useEffect pour charger les streams au chargement
    useEffect(() => {
        fetchStreamList();
    }, []);

    const fetchStreamList = async () => {
        try {
            const response = await fetch("/api/dashcam/v0/videos", {
                method: "GET",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Access-Token": sessionManager.getAccessToken() || "",
                },
            });

            if (!response.ok) {
                throw new Error(`Erreur HTTP: ${response.status}`);
            }

            const data: ApiResponse = await response.json();
            setStreamData(data);
        } catch (err) {
            const errorMessage = err instanceof Error ? err.message : 'Erreur inconnue';
            console.error(errorMessage);
        }
    };

    return (
        <section className="Home">
            <section className="last-moments">
                <h1>LAST MOMENTS</h1>
                <section className="videos">
                    {streamData && Object.entries(streamData.streams).length > 0 ? (
                        Object.entries(streamData.streams).map(([streamId, files]) => (
                            <Video
                                key={streamId}
                                title={streamId}
                                date={files[0].creation_date}
                                size={files[0].size_human}
                                sharedTo=""
                            />
                        ))
                    ) : (
                        <div>There is nothing to show</div>
                    )}
                </section>
            </section>
        </section>
    );
};

export default Home;