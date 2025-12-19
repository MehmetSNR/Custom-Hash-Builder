# 🔐 Custom Hash Builder

A modern, interactive Python GUI application that allows you to visually design custom hash pipelines by combining multiple hash functions and transformations in sequence.

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![Tkinter](https://img.shields.io/badge/GUI-Tkinter-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Available Hash Methods](#available-hash-methods)
- [Screenshots](#screenshots)
- [Export Options](#export-options)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

Custom Hash Builder is a drag-and-drop style GUI application built with Python's Tkinter that enables users to create complex hash pipelines without writing code. Simply click on hash methods from the left panel to add them to your pipeline, reorder them as needed, test with sample input, and export the final pipeline as Python code or JSON configuration.

Perfect for:
- Learning about different hash algorithms
- Creating custom hash functions for specific use cases
- Prototyping hash-based authentication systems
- Educational purposes and cryptography demonstrations

## ✨ Features

### 🎨 Modern Interface
- **Dark-themed UI** with clean, professional design
- **Color-coded hash methods** for easy identification
- **Responsive layout** that adapts to window resizing
- **Smooth scrolling** for long pipelines and method lists

### 🔧 Pipeline Builder
- **Click-to-add** hash methods from the sidebar
- **Visual pipeline** showing the sequence of operations
- **Reorder operations** with ▲/▼ buttons
- **Remove steps** individually with ✕ button
- **Clear all** to start fresh

### 🧪 Testing & Validation
- **Live testing** with custom input text
- **Instant results** displayed in the output panel
- **Error handling** with descriptive messages
- **Step-by-step execution** through the pipeline

### 💾 Export & Import
- **Python code export** - Generate ready-to-use Python functions
- **JSON configuration** - Save and share pipeline configurations
- **Import pipelines** - Load previously saved configurations
- **Portable code** - Exported code works standalone

## 🚀 Installation

### Prerequisites
- Python 3.10 or higher
- No external dependencies required (uses only Python standard library)

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/custom_hash_builder.git
cd custom_hash_builder
```

2. **Run the application**
```bash
python hash_builder_gui.py
```

That's it! The application uses only Python's built-in modules (`tkinter`, `hashlib`, `base64`, `json`).

## 📖 Usage

### Basic Workflow

1. **Launch the application**
   ```bash
   python hash_builder_gui.py
   ```

2. **Build your pipeline**
   - Browse available hash methods in the left panel
   - Click on any method to add it to the pipeline
   - The method appears in the center panel

3. **Organize your pipeline**
   - Use ▲ button to move a step up
   - Use ▼ button to move a step down
   - Use ✕ button to remove a step
   - Click "Clear All" to remove all steps

4. **Test your hash**
   - Enter sample text in the "Input Text" field (right panel)
   - Click "▶ Run Hash Pipeline"
   - View the result in the "Output" field

5. **Export your work**
   - Click "📄 Export as Python Code" to save as `.py` file
   - Click "📋 Export as JSON Config" to save configuration
   - Click "📥 Import JSON Config" to load a saved pipeline

### Example Pipeline

Here's an example of creating a custom hash:

1. Add **SHA-256** (first hash)
2. Add **Base64 Encode** (encode the hash)
3. Add **Upper** (convert to uppercase)
4. Add **Reverse** (reverse the string)

Input: `Hello World!`
Output: Custom transformed hash based on your pipeline

## 🔑 Available Hash Methods

### Cryptographic Hash Functions
| Method | Description | Output Size |
|--------|-------------|-------------|
| **MD5** | Fast but deprecated hash | 128-bit |
| **SHA-1** | Legacy secure hash | 160-bit |
| **SHA-256** | Industry standard | 256-bit |
| **SHA-384** | Extended SHA-2 | 384-bit |
| **SHA-512** | Maximum SHA-2 | 512-bit |
| **SHA3-256** | Modern SHA-3 variant | 256-bit |
| **SHA3-512** | Maximum SHA-3 | 512-bit |
| **BLAKE2b** | Fast, secure modern hash | 512-bit |
| **BLAKE2s** | Optimized for 32-bit | 256-bit |

### Encoding & Transformations
| Method | Description |
|--------|-------------|
| **Base64 Encode** | Convert to Base64 |
| **Base64 Decode** | Decode from Base64 |
| **Hex Encode** | Convert to hexadecimal |
| **Reverse** | Reverse the string |
| **Upper** | Convert to uppercase |
| **Lower** | Convert to lowercase |

## 🖼️ Screenshots

### Main Interface
The application features three main panels:
- **Left Panel**: Available hash methods with color-coded cards
- **Center Panel**: Your custom hash pipeline with controls
- **Right Panel**: Testing area and export options

### Pipeline Example
Each step in the pipeline shows:
- Step number
- Method name with color indicator
- Control buttons (move up/down, remove)

## 📦 Export Options

### Python Code Export

Generates a standalone Python function:

```python
import hashlib
import base64

def custom_hash(data: str) -> str:
    """
    Custom hash function generated by Hash Builder
    Pipeline: SHA-256 → Base64 Encode → Upper
    """
    result = data.encode('utf-8')
    
    result = hashlib.sha256(result if isinstance(result, bytes) else result.encode()).hexdigest()
    result = base64.b64encode(result if isinstance(result, bytes) else result.encode()).decode()
    result = result.upper() if isinstance(result, str) else result.decode().upper()
    
    return result

if __name__ == "__main__":
    test_input = "Hello World!"
    print(f"Input: {test_input}")
    print(f"Output: {custom_hash(test_input)}")
```

### JSON Configuration Export

Saves your pipeline as a portable configuration:

```json
{
  "name": "Custom Hash Pipeline",
  "version": "1.0",
  "pipeline": [
    {
      "method": "SHA-256",
      "description": "256-bit hash"
    },
    {
      "method": "Base64 Encode",
      "description": "Encoding step"
    },
    {
      "method": "Upper",
      "description": "Uppercase"
    }
  ]
}
```

## 🛠️ Technical Details

### Architecture
- **GUI Framework**: Tkinter (Python standard library)
- **Hash Library**: hashlib (Python standard library)
- **Encoding**: base64 (Python standard library)
- **Configuration**: json (Python standard library)

### File Structure
```
custom_hash_builder/
├── hash_builder_gui.py    # Main application
├── README.md              # This file


### Key Classes
- `HashMethod`: Represents a hash method with name, description, and color
- `DraggableLabel`: Visual card for each hash method in the sidebar
- `PipelineItem`: Visual representation of a step in the pipeline
- `HashBuilderApp`: Main application class managing the GUI and logic

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/AmazingFeature
   ```
3. **Commit your changes**
   ```bash
   git commit -m 'Add some AmazingFeature'
   ```
4. **Push to the branch**
   ```bash
   git push origin feature/AmazingFeature
   ```
5. **Open a Pull Request**

### Ideas for Contributions
- Add more hash algorithms (scrypt, argon2, etc.)
- Implement actual drag-and-drop functionality
- Add dark/light theme toggle
- Create unit tests
- Add pipeline validation
- Implement undo/redo functionality
- Add keyboard shortcuts

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with Python's excellent standard library
- Inspired by visual programming tools
- Color scheme designed for accessibility

## 📧 Contact

For questions, suggestions, or issues, please open an issue on GitHub.

---

**Made with ❤️ using Python and Tkinter**
