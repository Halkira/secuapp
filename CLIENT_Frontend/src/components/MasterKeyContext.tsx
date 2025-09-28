import {createContext, ReactNode, useContext} from 'react';

interface MasterKeyContextType {
    mk: string | null;
    setMk: (key: string | null) => void;
}

const MyContext = createContext<MasterKeyContextType | null>(null);

export const useMyContext = () => {
    const context = useContext(MyContext);
    if (context === null) {
        throw new Error('useMyContext must be used within a MyContextProvider');
    }
    return context;
};

export const MyContextProvider = ({ children, value }: { children: ReactNode; value: MasterKeyContextType }) => {
    return <MyContext.Provider value={value}>{children}</MyContext.Provider>;
};