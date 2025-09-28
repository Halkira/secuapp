import React from 'react';

interface ProgressBarProps {
    progress: number;
    color?: string;
    height?: number;
    label?: string;
}

const ProgressBar: React.FC<ProgressBarProps> = ({
     progress,
     color = '#268ACA',
     height = 10,
     label
}) => {
    return (
        <div style={{ marginBottom: '15px' }}>
            <div style={{ width: '100%', backgroundColor: '#444', borderRadius: '4px', overflow: 'hidden' }}>
                <div
                    style={{
                        height: `${height}px`,
                        width: `${progress}%`,
                        backgroundColor: color,
                        transition: 'width 0.3s ease-in-out'
                    }}
                />
            </div>
            {label && (
                <p style={{ textAlign: 'center', marginTop: '5px' }}>
                    {label}: {progress}%
                </p>
            )}
        </div>
    );
};

export default ProgressBar;