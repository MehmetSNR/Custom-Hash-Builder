import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import hashlib
import base64
import json


class HashMethod:
    """Hash method representation"""
    def __init__(self, name, description, color):
        self.name = name
        self.description = description
        self.color = color


class DraggableLabel(tk.Frame):
    """Draggable hash method card"""
    def __init__(self, parent, method, on_drag_start, **kwargs):
        super().__init__(parent, **kwargs)
        self.method = method
        self.on_drag_start = on_drag_start
        
        self.configure(bg=method.color, cursor="hand2")
        
        self.label = tk.Label(
            self,
            text=method.name,
            font=("Segoe UI", 11, "bold"),
            bg=method.color,
            fg="white",
            padx=15,
            pady=10
        )
        self.label.pack(fill=tk.X)
        
        self.desc_label = tk.Label(
            self,
            text=method.description,
            font=("Segoe UI", 8),
            bg=method.color,
            fg="#dddddd",
            padx=15
        )
        self.desc_label.pack(fill=tk.X, pady=(0, 8))
        
        # Bind drag events
        self.bind("<Button-1>", self._on_click)
        self.label.bind("<Button-1>", self._on_click)
        self.desc_label.bind("<Button-1>", self._on_click)
        
    def _on_click(self, event):
        self.on_drag_start(self.method)


class PipelineItem(tk.Frame):
    """Item in the hash pipeline"""
    def __init__(self, parent, method, index, on_remove, on_move_up, on_move_down, **kwargs):
        super().__init__(parent, **kwargs)
        self.method = method
        self.index = index
        
        self.configure(bg="#2d2d2d", highlightbackground=method.color, highlightthickness=2)
        
        # Main container
        container = tk.Frame(self, bg="#2d2d2d")
        container.pack(fill=tk.X, padx=8, pady=8)
        
        # Index number
        idx_label = tk.Label(
            container,
            text=f"{index + 1}",
            font=("Segoe UI", 12, "bold"),
            bg=method.color,
            fg="white",
            width=3,
            height=1
        )
        idx_label.pack(side=tk.LEFT, padx=(0, 10))
        
        # Method name
        name_label = tk.Label(
            container,
            text=method.name,
            font=("Segoe UI", 11, "bold"),
            bg="#2d2d2d",
            fg="white"
        )
        name_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Control buttons
        btn_frame = tk.Frame(container, bg="#2d2d2d")
        btn_frame.pack(side=tk.RIGHT)
        
        up_btn = tk.Button(
            btn_frame,
            text="▲",
            font=("Segoe UI", 8),
            bg="#404040",
            fg="white",
            relief=tk.FLAT,
            width=3,
            command=lambda: on_move_up(index)
        )
        up_btn.pack(side=tk.LEFT, padx=2)
        
        down_btn = tk.Button(
            btn_frame,
            text="▼",
            font=("Segoe UI", 8),
            bg="#404040",
            fg="white",
            relief=tk.FLAT,
            width=3,
            command=lambda: on_move_down(index)
        )
        down_btn.pack(side=tk.LEFT, padx=2)
        
        remove_btn = tk.Button(
            btn_frame,
            text="✕",
            font=("Segoe UI", 8, "bold"),
            bg="#e74c3c",
            fg="white",
            relief=tk.FLAT,
            width=3,
            command=lambda: on_remove(index)
        )
        remove_btn.pack(side=tk.LEFT, padx=(2, 0))


class HashBuilderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Custom Hash Builder")
        self.root.geometry("1100x700")
        self.root.configure(bg="#1a1a2e")
        self.root.minsize(900, 600)
        
        # Pipeline storage
        self.pipeline = []
        
        # Available hash methods
        self.hash_methods = [
            HashMethod("MD5", "128-bit hash", "#e74c3c"),
            HashMethod("SHA-1", "160-bit hash", "#e67e22"),
            HashMethod("SHA-256", "256-bit hash", "#2ecc71"),
            HashMethod("SHA-384", "384-bit hash", "#3498db"),
            HashMethod("SHA-512", "512-bit hash", "#9b59b6"),
            HashMethod("SHA3-256", "SHA-3 256-bit", "#1abc9c"),
            HashMethod("SHA3-512", "SHA-3 512-bit", "#34495e"),
            HashMethod("BLAKE2b", "Fast secure hash", "#e91e63"),
            HashMethod("BLAKE2s", "Optimized for 32-bit", "#673ab7"),
            HashMethod("Base64 Encode", "Encoding step", "#00bcd4"),
            HashMethod("Base64 Decode", "Decoding step", "#009688"),
            HashMethod("Hex Encode", "To hexadecimal", "#ff9800"),
            HashMethod("Reverse", "Reverse string", "#795548"),
            HashMethod("Upper", "Uppercase", "#607d8b"),
            HashMethod("Lower", "Lowercase", "#8bc34a"),
        ]
        
        self._setup_styles()
        self._create_ui()
        
    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure(
            "Dark.TFrame",
            background="#1a1a2e"
        )
        
        style.configure(
            "Card.TFrame",
            background="#16213e"
        )
        
    def _create_ui(self):
        # Main container
        main_frame = tk.Frame(self.root, bg="#1a1a2e")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Header
        header = tk.Frame(main_frame, bg="#1a1a2e")
        header.pack(fill=tk.X, pady=(0, 15))
        
        title = tk.Label(
            header,
            text="🔐 Custom Hash Builder",
            font=("Segoe UI", 24, "bold"),
            bg="#1a1a2e",
            fg="white"
        )
        title.pack(side=tk.LEFT)
        
        subtitle = tk.Label(
            header,
            text="Drag methods to build your custom hash pipeline",
            font=("Segoe UI", 11),
            bg="#1a1a2e",
            fg="#888"
        )
        subtitle.pack(side=tk.LEFT, padx=(20, 0), pady=(10, 0))
        
        # Content area
        content = tk.Frame(main_frame, bg="#1a1a2e")
        content.pack(fill=tk.BOTH, expand=True)
        
        # Left panel - Hash Methods
        left_panel = tk.Frame(content, bg="#16213e", width=280)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 15))
        left_panel.pack_propagate(False)
        
        left_header = tk.Label(
            left_panel,
            text="📦 Hash Methods",
            font=("Segoe UI", 14, "bold"),
            bg="#16213e",
            fg="white",
            pady=15
        )
        left_header.pack(fill=tk.X)
        
        left_hint = tk.Label(
            left_panel,
            text="Click to add to pipeline →",
            font=("Segoe UI", 9),
            bg="#16213e",
            fg="#666"
        )
        left_hint.pack(fill=tk.X, pady=(0, 10))
        
        # Scrollable methods list
        methods_canvas = tk.Canvas(left_panel, bg="#16213e", highlightthickness=0)
        methods_scrollbar = ttk.Scrollbar(left_panel, orient="vertical", command=methods_canvas.yview)
        methods_frame = tk.Frame(methods_canvas, bg="#16213e")
        
        methods_canvas.configure(yscrollcommand=methods_scrollbar.set)
        methods_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        methods_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        canvas_window = methods_canvas.create_window((0, 0), window=methods_frame, anchor="nw")
        
        def configure_scroll(event):
            methods_canvas.configure(scrollregion=methods_canvas.bbox("all"))
            methods_canvas.itemconfig(canvas_window, width=event.width)
        
        methods_frame.bind("<Configure>", lambda e: methods_canvas.configure(scrollregion=methods_canvas.bbox("all")))
        methods_canvas.bind("<Configure>", configure_scroll)
        
        # Add method cards
        for method in self.hash_methods:
            card = DraggableLabel(
                methods_frame,
                method,
                self._add_to_pipeline
            )
            card.pack(fill=tk.X, padx=10, pady=5)
        
        # Center panel - Pipeline
        center_panel = tk.Frame(content, bg="#0f3460")
        center_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 15))
        
        center_header = tk.Frame(center_panel, bg="#0f3460")
        center_header.pack(fill=tk.X, padx=15, pady=15)
        
        pipeline_title = tk.Label(
            center_header,
            text="⚡ Hash Pipeline",
            font=("Segoe UI", 14, "bold"),
            bg="#0f3460",
            fg="white"
        )
        pipeline_title.pack(side=tk.LEFT)
        
        clear_btn = tk.Button(
            center_header,
            text="🗑 Clear All",
            font=("Segoe UI", 9),
            bg="#e74c3c",
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=5,
            command=self._clear_pipeline
        )
        clear_btn.pack(side=tk.RIGHT)
        
        # Pipeline container with scroll
        pipeline_container = tk.Frame(center_panel, bg="#0f3460")
        pipeline_container.pack(fill=tk.BOTH, expand=True, padx=15)
        
        self.pipeline_canvas = tk.Canvas(pipeline_container, bg="#1a1a2e", highlightthickness=0)
        pipeline_scrollbar = ttk.Scrollbar(pipeline_container, orient="vertical", command=self.pipeline_canvas.yview)
        self.pipeline_frame = tk.Frame(self.pipeline_canvas, bg="#1a1a2e")
        
        self.pipeline_canvas.configure(yscrollcommand=pipeline_scrollbar.set)
        pipeline_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.pipeline_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.pipeline_window = self.pipeline_canvas.create_window((0, 0), window=self.pipeline_frame, anchor="nw")
        
        self.pipeline_frame.bind("<Configure>", lambda e: self.pipeline_canvas.configure(scrollregion=self.pipeline_canvas.bbox("all")))
        self.pipeline_canvas.bind("<Configure>", lambda e: self.pipeline_canvas.itemconfig(self.pipeline_window, width=e.width))
        
        # Empty state
        self.empty_label = tk.Label(
            self.pipeline_frame,
            text="🎯 Click methods from left panel\nto build your hash pipeline",
            font=("Segoe UI", 12),
            bg="#1a1a2e",
            fg="#666",
            pady=50
        )
        self.empty_label.pack(fill=tk.X)
        
        # Right panel - Test & Output
        right_panel = tk.Frame(content, bg="#16213e", width=320)
        right_panel.pack(side=tk.RIGHT, fill=tk.Y)
        right_panel.pack_propagate(False)
        
        # Test section
        test_header = tk.Label(
            right_panel,
            text="🧪 Test Your Hash",
            font=("Segoe UI", 14, "bold"),
            bg="#16213e",
            fg="white",
            pady=15
        )
        test_header.pack(fill=tk.X)
        
        input_label = tk.Label(
            right_panel,
            text="Input Text:",
            font=("Segoe UI", 10),
            bg="#16213e",
            fg="#aaa",
            anchor="w",
            padx=15
        )
        input_label.pack(fill=tk.X)
        
        self.input_text = tk.Text(
            right_panel,
            height=4,
            font=("Consolas", 10),
            bg="#1a1a2e",
            fg="white",
            insertbackground="white",
            relief=tk.FLAT,
            padx=10,
            pady=10
        )
        self.input_text.pack(fill=tk.X, padx=15, pady=(5, 10))
        self.input_text.insert("1.0", "Hello World!")
        
        test_btn = tk.Button(
            right_panel,
            text="▶ Run Hash Pipeline",
            font=("Segoe UI", 11, "bold"),
            bg="#2ecc71",
            fg="white",
            relief=tk.FLAT,
            pady=10,
            command=self._run_pipeline
        )
        test_btn.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        output_label = tk.Label(
            right_panel,
            text="Output:",
            font=("Segoe UI", 10),
            bg="#16213e",
            fg="#aaa",
            anchor="w",
            padx=15
        )
        output_label.pack(fill=tk.X)
        
        self.output_text = tk.Text(
            right_panel,
            height=6,
            font=("Consolas", 10),
            bg="#1a1a2e",
            fg="#2ecc71",
            relief=tk.FLAT,
            padx=10,
            pady=10,
            wrap=tk.WORD
        )
        self.output_text.pack(fill=tk.X, padx=15, pady=(5, 15))
        
        # Separator
        sep = tk.Frame(right_panel, bg="#333", height=2)
        sep.pack(fill=tk.X, padx=15, pady=10)
        
        # Export section
        export_header = tk.Label(
            right_panel,
            text="💾 Export",
            font=("Segoe UI", 14, "bold"),
            bg="#16213e",
            fg="white",
            pady=10
        )
        export_header.pack(fill=tk.X)
        
        export_py_btn = tk.Button(
            right_panel,
            text="📄 Export as Python Code",
            font=("Segoe UI", 10),
            bg="#3498db",
            fg="white",
            relief=tk.FLAT,
            pady=8,
            command=self._export_python
        )
        export_py_btn.pack(fill=tk.X, padx=15, pady=5)
        
        export_json_btn = tk.Button(
            right_panel,
            text="📋 Export as JSON Config",
            font=("Segoe UI", 10),
            bg="#9b59b6",
            fg="white",
            relief=tk.FLAT,
            pady=8,
            command=self._export_json
        )
        export_json_btn.pack(fill=tk.X, padx=15, pady=5)
        
        import_btn = tk.Button(
            right_panel,
            text="📥 Import JSON Config",
            font=("Segoe UI", 10),
            bg="#e67e22",
            fg="white",
            relief=tk.FLAT,
            pady=8,
            command=self._import_json
        )
        import_btn.pack(fill=tk.X, padx=15, pady=5)
        
    def _add_to_pipeline(self, method):
        """Add a method to the pipeline"""
        self.pipeline.append(method)
        self._refresh_pipeline()
        
    def _remove_from_pipeline(self, index):
        """Remove a method from the pipeline"""
        if 0 <= index < len(self.pipeline):
            self.pipeline.pop(index)
            self._refresh_pipeline()
            
    def _move_up(self, index):
        """Move item up in pipeline"""
        if index > 0:
            self.pipeline[index], self.pipeline[index-1] = self.pipeline[index-1], self.pipeline[index]
            self._refresh_pipeline()
            
    def _move_down(self, index):
        """Move item down in pipeline"""
        if index < len(self.pipeline) - 1:
            self.pipeline[index], self.pipeline[index+1] = self.pipeline[index+1], self.pipeline[index]
            self._refresh_pipeline()
            
    def _clear_pipeline(self):
        """Clear all items from pipeline"""
        self.pipeline.clear()
        self._refresh_pipeline()
        
    def _refresh_pipeline(self):
        """Refresh the pipeline display"""
        # Clear current items
        for widget in self.pipeline_frame.winfo_children():
            widget.destroy()
            
        if not self.pipeline:
            self.empty_label = tk.Label(
                self.pipeline_frame,
                text="🎯 Click methods from left panel\nto build your hash pipeline",
                font=("Segoe UI", 12),
                bg="#1a1a2e",
                fg="#666",
                pady=50
            )
            self.empty_label.pack(fill=tk.X)
        else:
            for i, method in enumerate(self.pipeline):
                item = PipelineItem(
                    self.pipeline_frame,
                    method,
                    i,
                    self._remove_from_pipeline,
                    self._move_up,
                    self._move_down
                )
                item.pack(fill=tk.X, pady=5, padx=5)
                
                # Add arrow between items
                if i < len(self.pipeline) - 1:
                    arrow = tk.Label(
                        self.pipeline_frame,
                        text="↓",
                        font=("Segoe UI", 16),
                        bg="#1a1a2e",
                        fg="#666"
                    )
                    arrow.pack(pady=2)
                    
    def _apply_hash_method(self, data, method_name):
        """Apply a single hash method to data"""
        try:
            if isinstance(data, str):
                data_bytes = data.encode('utf-8')
            else:
                data_bytes = data
                
            if method_name == "MD5":
                return hashlib.md5(data_bytes).hexdigest()
            elif method_name == "SHA-1":
                return hashlib.sha1(data_bytes).hexdigest()
            elif method_name == "SHA-256":
                return hashlib.sha256(data_bytes).hexdigest()
            elif method_name == "SHA-384":
                return hashlib.sha384(data_bytes).hexdigest()
            elif method_name == "SHA-512":
                return hashlib.sha512(data_bytes).hexdigest()
            elif method_name == "SHA3-256":
                return hashlib.sha3_256(data_bytes).hexdigest()
            elif method_name == "SHA3-512":
                return hashlib.sha3_512(data_bytes).hexdigest()
            elif method_name == "BLAKE2b":
                return hashlib.blake2b(data_bytes).hexdigest()
            elif method_name == "BLAKE2s":
                return hashlib.blake2s(data_bytes).hexdigest()
            elif method_name == "Base64 Encode":
                return base64.b64encode(data_bytes).decode('utf-8')
            elif method_name == "Base64 Decode":
                return base64.b64decode(data_bytes).decode('utf-8')
            elif method_name == "Hex Encode":
                return data_bytes.hex()
            elif method_name == "Reverse":
                return data[::-1] if isinstance(data, str) else data_bytes[::-1].decode('utf-8')
            elif method_name == "Upper":
                return data.upper() if isinstance(data, str) else data_bytes.decode('utf-8').upper()
            elif method_name == "Lower":
                return data.lower() if isinstance(data, str) else data_bytes.decode('utf-8').lower()
            else:
                return data
        except Exception as e:
            raise Exception(f"Error in {method_name}: {str(e)}")
            
    def _run_pipeline(self):
        """Run the hash pipeline on input"""
        if not self.pipeline:
            messagebox.showwarning("Warning", "Pipeline is empty! Add some hash methods first.")
            return
            
        input_data = self.input_text.get("1.0", tk.END).strip()
        if not input_data:
            messagebox.showwarning("Warning", "Please enter some input text.")
            return
            
        try:
            result = input_data
            for method in self.pipeline:
                result = self._apply_hash_method(result, method.name)
                
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", result)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            
    def _export_python(self):
        """Export pipeline as Python code"""
        if not self.pipeline:
            messagebox.showwarning("Warning", "Pipeline is empty!")
            return
            
        code = '''import hashlib
import base64


def custom_hash(data: str) -> str:
    """
    Custom hash function generated by Hash Builder
    Pipeline: {pipeline_desc}
    """
    result = data.encode('utf-8')
    
'''
        pipeline_desc = " → ".join([m.name for m in self.pipeline])
        code = code.format(pipeline_desc=pipeline_desc)
        
        for method in self.pipeline:
            if method.name == "MD5":
                code += "    result = hashlib.md5(result if isinstance(result, bytes) else result.encode()).hexdigest()\n"
            elif method.name == "SHA-1":
                code += "    result = hashlib.sha1(result if isinstance(result, bytes) else result.encode()).hexdigest()\n"
            elif method.name == "SHA-256":
                code += "    result = hashlib.sha256(result if isinstance(result, bytes) else result.encode()).hexdigest()\n"
            elif method.name == "SHA-384":
                code += "    result = hashlib.sha384(result if isinstance(result, bytes) else result.encode()).hexdigest()\n"
            elif method.name == "SHA-512":
                code += "    result = hashlib.sha512(result if isinstance(result, bytes) else result.encode()).hexdigest()\n"
            elif method.name == "SHA3-256":
                code += "    result = hashlib.sha3_256(result if isinstance(result, bytes) else result.encode()).hexdigest()\n"
            elif method.name == "SHA3-512":
                code += "    result = hashlib.sha3_512(result if isinstance(result, bytes) else result.encode()).hexdigest()\n"
            elif method.name == "BLAKE2b":
                code += "    result = hashlib.blake2b(result if isinstance(result, bytes) else result.encode()).hexdigest()\n"
            elif method.name == "BLAKE2s":
                code += "    result = hashlib.blake2s(result if isinstance(result, bytes) else result.encode()).hexdigest()\n"
            elif method.name == "Base64 Encode":
                code += "    result = base64.b64encode(result if isinstance(result, bytes) else result.encode()).decode()\n"
            elif method.name == "Base64 Decode":
                code += "    result = base64.b64decode(result if isinstance(result, bytes) else result.encode()).decode()\n"
            elif method.name == "Hex Encode":
                code += "    result = (result if isinstance(result, bytes) else result.encode()).hex()\n"
            elif method.name == "Reverse":
                code += "    result = result[::-1] if isinstance(result, str) else result.decode()[::-1]\n"
            elif method.name == "Upper":
                code += "    result = result.upper() if isinstance(result, str) else result.decode().upper()\n"
            elif method.name == "Lower":
                code += "    result = result.lower() if isinstance(result, str) else result.decode().lower()\n"
                
        code += '''
    return result


if __name__ == "__main__":
    test_input = "Hello World!"
    print(f"Input: {test_input}")
    print(f"Output: {custom_hash(test_input)}")
'''
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".py",
            filetypes=[("Python files", "*.py")],
            title="Save Python Code"
        )
        
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(code)
            messagebox.showinfo("Success", f"Python code saved to:\n{file_path}")
            
    def _export_json(self):
        """Export pipeline as JSON config"""
        if not self.pipeline:
            messagebox.showwarning("Warning", "Pipeline is empty!")
            return
            
        config = {
            "name": "Custom Hash Pipeline",
            "version": "1.0",
            "pipeline": [{"method": m.name, "description": m.description} for m in self.pipeline]
        }
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            title="Save JSON Config"
        )
        
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            messagebox.showinfo("Success", f"JSON config saved to:\n{file_path}")
            
    def _import_json(self):
        """Import pipeline from JSON config"""
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json")],
            title="Open JSON Config"
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    
                self.pipeline.clear()
                method_map = {m.name: m for m in self.hash_methods}
                
                for item in config.get("pipeline", []):
                    method_name = item.get("method")
                    if method_name in method_map:
                        self.pipeline.append(method_map[method_name])
                        
                self._refresh_pipeline()
                messagebox.showinfo("Success", "Pipeline imported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import: {str(e)}")


def main():
    root = tk.Tk()
    app = HashBuilderApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
