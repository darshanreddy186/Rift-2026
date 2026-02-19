import React, { useState, useCallback } from 'react';
import Papa from 'papaparse';
import { Upload, FileText, AlertCircle, CheckCircle2, Loader2 } from 'lucide-react';
import { Transaction } from '../types';
import { cn } from '../lib/utils';

interface FileUploadProps {
  onDataLoaded: (data: Transaction[]) => void;
}

const FileUpload: React.FC<FileUploadProps> = ({ onDataLoaded }) => {
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const processFile = (file: File) => {
    setIsLoading(true);
    setError(null);

    Papa.parse(file, {
      header: true,
      skipEmptyLines: true,
      dynamicTyping: true,
      complete: (results) => {
        const data = results.data as any[];
        
        // Validation
        const requiredColumns = ['transaction_id', 'sender_id', 'receiver_id', 'amount', 'timestamp'];
        const headers = results.meta.fields || [];
        const missing = requiredColumns.filter(col => !headers.includes(col));

        if (missing.length > 0) {
          setError(`Missing required columns: ${missing.join(', ')}`);
          setIsLoading(false);
          return;
        }

        const validData: Transaction[] = data.map(row => ({
          transaction_id: String(row.transaction_id),
          sender_id: String(row.sender_id),
          receiver_id: String(row.receiver_id),
          amount: Number(row.amount),
          timestamp: String(row.timestamp)
        }));

        onDataLoaded(validData);
        setIsLoading(false);
      },
      error: (err) => {
        setError(`Failed to parse CSV: ${err.message}`);
        setIsLoading(false);
      }
    });
  };

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file && file.type === 'text/csv') {
      processFile(file);
    } else {
      setError('Please upload a valid CSV file.');
    }
  }, []);

  const onFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) processFile(file);
  };

  return (
    <div className="w-full max-w-2xl mx-auto">
      <div
        onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={onDrop}
        className={cn(
          "relative group cursor-pointer border-2 border-dashed rounded-2xl p-12 transition-all duration-300 flex flex-col items-center justify-center gap-4",
          isDragging ? "border-blue-500 bg-blue-50" : "border-slate-300 hover:border-slate-400 bg-white shadow-sm",
          isLoading && "pointer-events-none opacity-60"
        )}
      >
        <input
          type="file"
          accept=".csv"
          onChange={onFileChange}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
        />
        
        <div className={cn(
          "w-16 h-16 rounded-full flex items-center justify-center transition-colors",
          isDragging ? "bg-blue-100 text-blue-600" : "bg-slate-100 text-slate-500 group-hover:bg-slate-200"
        )}>
          {isLoading ? <Loader2 className="w-8 h-8 animate-spin" /> : <Upload className="w-8 h-8" />}
        </div>

        <div className="text-center">
          <h3 className="text-lg font-semibold text-slate-900">
            {isLoading ? "Processing Transaction Data..." : "Upload Transaction Dataset"}
          </h3>
          <p className="text-sm text-slate-500 mt-1">
            Drag and drop your CSV file here, or click to browse
          </p>
        </div>

        <div className="flex items-center gap-4 mt-4 px-4 py-2 bg-slate-50 rounded-lg border border-slate-200 text-[10px] font-mono text-slate-400 uppercase tracking-widest">
          <span>transaction_id</span>
          <span>sender_id</span>
          <span>receiver_id</span>
          <span>amount</span>
          <span>timestamp</span>
        </div>

        {error && (
          <div className="mt-4 flex items-center gap-2 text-red-600 bg-red-50 px-4 py-2 rounded-lg border border-red-100 text-sm">
            <AlertCircle className="w-4 h-4" />
            <span>{error}</span>
          </div>
        )}
      </div>
      
      <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 bg-white rounded-xl border border-slate-200 shadow-sm">
          <div className="flex items-center gap-2 text-blue-600 mb-1">
            <CheckCircle2 className="w-4 h-4" />
            <span className="text-xs font-bold uppercase tracking-wider">Cycles</span>
          </div>
          <p className="text-xs text-slate-500">Detects circular fund routing (length 3-5)</p>
        </div>
        <div className="p-4 bg-white rounded-xl border border-slate-200 shadow-sm">
          <div className="flex items-center gap-2 text-emerald-600 mb-1">
            <CheckCircle2 className="w-4 h-4" />
            <span className="text-xs font-bold uppercase tracking-wider">Smurfing</span>
          </div>
          <p className="text-xs text-slate-500">Identifies fan-in/fan-out patterns (72h window)</p>
        </div>
        <div className="p-4 bg-white rounded-xl border border-slate-200 shadow-sm">
          <div className="flex items-center gap-2 text-amber-600 mb-1">
            <CheckCircle2 className="w-4 h-4" />
            <span className="text-xs font-bold uppercase tracking-wider">Shells</span>
          </div>
          <p className="text-xs text-slate-500">Exposes multi-hop layered shell networks</p>
        </div>
      </div>
    </div>
  );
};

export default FileUpload;
