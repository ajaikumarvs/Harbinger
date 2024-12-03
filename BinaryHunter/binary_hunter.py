import os
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk

ctk.set_appearance_mode("dark")  # Modes: system (default), light, dark
ctk.set_default_color_theme("blue")  # Themes: blue (default), dark-blue, green

class FileManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced File Manager")
        self.root.geometry("800x600")
        
        self.current_directory = os.path.expanduser("~")  
        
        self.frame = ctk.CTkFrame(self.root)
        self.frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.path_label = ctk.CTkLabel(self.frame, text="Current Path:")
        self.path_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        
        self.path_entry = ctk.CTkEntry(self.frame)
        self.path_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")
        self.path_entry.bind("<Return>", self.change_directory)  
        
        self.browse_button = ctk.CTkButton(self.frame, text="Browse", command=self.browse_directory)
        self.browse_button.grid(row=0, column=2, padx=10, pady=5)

        self.file_listbox = tk.Listbox(self.frame, height=20, width=60, selectmode=tk.SINGLE)
        self.file_listbox.grid(row=1, column=0, columnspan=3, padx=10, pady=10)
        self.file_listbox.bind("<Double-1>", self.open_file)
       
        self.load_directory(self.current_directory)
        
        self.delete_button = ctk.CTkButton(self.frame, text="Delete", command=self.delete_file)
        self.delete_button.grid(row=2, column=0, padx=10, pady=5)

        self.copy_button = ctk.CTkButton(self.frame, text="Copy", command=self.copy_file)
        self.copy_button.grid(row=2, column=1, padx=10, pady=5)

        self.move_button = ctk.CTkButton(self.frame, text="Move", command=self.move_file)
        self.move_button.grid(row=2, column=2, padx=10, pady=5)

        self.refresh_button = ctk.CTkButton(self.frame, text="Refresh", command=self.refresh_directory)
        self.refresh_button.grid(row=3, column=0, columnspan=3, pady=10)

    def load_directory(self, directory):
        """Loads the contents of the directory into the listbox."""
        self.current_directory = directory
        self.path_entry.delete(0, tk.END)
        self.path_entry.insert(0, directory)
        
        self.file_listbox.delete(0, tk.END)
        try:
            for item in os.listdir(directory):
                self.file_listbox.insert(tk.END, item)
        except PermissionError:
            messagebox.showerror("Permission Denied", "You do not have permission to access this folder.")
    
    def change_directory(self, event=None):
        """Change the directory based on the entered path."""
        new_directory = self.path_entry.get()
        if os.path.isdir(new_directory):
            self.load_directory(new_directory)
        else:
            messagebox.showerror("Invalid Path", f"The path '{new_directory}' is not a valid directory.")
    
    def browse_directory(self):
        """Allow the user to browse and select a directory."""
        folder = filedialog.askdirectory(initialdir=self.current_directory)
        if folder:
            self.load_directory(folder)
    
    def open_file(self, event):
        """Open a file or directory."""
        selected_item = self.file_listbox.get(self.file_listbox.curselection())
        full_path = os.path.join(self.current_directory, selected_item)
        
        if os.path.isdir(full_path):
            self.load_directory(full_path)
        else:
            messagebox.showinfo("File Info", f"Selected file: {full_path}\nSize: {os.path.getsize(full_path)} bytes")
    
    def refresh_directory(self):
        """Refresh the current directory contents."""
        self.load_directory(self.current_directory)
    
    def delete_file(self):
        """Delete the selected file or folder."""
        selected_item = self.file_listbox.get(self.file_listbox.curselection())
        full_path = os.path.join(self.current_directory, selected_item)
        
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{selected_item}'?"):
            try:
                if os.path.isdir(full_path):
                    shutil.rmtree(full_path)  
                else:
                    os.remove(full_path)  
                self.refresh_directory()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete file/folder: {e}")
    
    def copy_file(self):
        """Copy the selected file or folder."""
        selected_item = self.file_listbox.get(self.file_listbox.curselection())
        full_path = os.path.join(self.current_directory, selected_item)
        
        destination = filedialog.askdirectory(initialdir=self.current_directory)
        if destination:
            try:
                if os.path.isdir(full_path):
                    shutil.copytree(full_path, os.path.join(destination, selected_item))  # Copy directory
                else:
                    shutil.copy(full_path, destination)  # Copy file
                messagebox.showinfo("Success", "File/Folder copied successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to copy file/folder: {e}")
    
    def move_file(self):
        """Move the selected file or folder."""
        selected_item = self.file_listbox.get(self.file_listbox.curselection())
        full_path = os.path.join(self.current_directory, selected_item)
        
        destination = filedialog.askdirectory(initialdir=self.current_directory)
        if destination:
            try:
                shutil.move(full_path, os.path.join(destination, selected_item))  
                self.refresh_directory()
                messagebox.showinfo("Success", "File/Folder moved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to move file/folder: {e}")

root = ctk.CTk()
app = FileManagerApp(root)
root.mainloop()
