# Contributing to Snakebite

Thanks for your interest in contributing! Here's how you can help.

## Getting Started

1. **Fork** the repository
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/Snakebite.git
   cd Snakebite
   ```
3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
4. **Create a branch** for your feature or fix:
   ```bash
   git checkout -b feature/my-new-module
   ```

## Adding a New Module

1. Create your module in `modules/` following the existing pattern
2. Each scan module should:
   - Accept `(session, url)` as its first two parameters
   - Be an `async` function
   - Return a `dict` or `list` of findings
   - Use `console.print()` from `modules.core` for output
3. Import and wire your module into `snakebite.py`
4. Test against a **local or authorized** target

## Code Style

- Follow PEP 8 guidelines
- Use meaningful variable and function names
- Add docstrings to public functions
- Keep modules focused — one scanner per file

## Pull Request Process

1. Ensure your code runs without errors
2. Update `CHANGELOG.md` if applicable
3. Submit a PR with a clear description of what your module does
4. Reference any related issues

## Code of Conduct

- Be respectful and constructive
- This tool is for **defensive security** — we do not support malicious use
- All contributions must comply with the MIT License

## Questions?

Open an issue or reach out to [@xKILLERDEADx](https://github.com/xKILLERDEADx).
