# KISS - A modern OSINT Toolkit.

A modern OSINT toolkit for comprehensive intelligence gathering with structured query support.

[Python 3.8+](https://python.org) • [MIT License](LICENSE) • [Documentation](docs/)

</div>

## Features

### Multi-Input Support
- **IP Addresses**: Geolocation, network intelligence, threat assessment
- **Email Addresses**: Breach detection, verification, comprehensive intelligence gathering
- **Phone Numbers**: International format support, carrier analysis, geographic intelligence
- **Usernames**: Cross-platform presence analysis and online footprint investigation
- **Physical Addresses**: International address lookup and verification services
- **Password Hashes**: Reverse password lookup against breach databases
- **Structured Queries**: Advanced filtering with field syntax (planned)

### Architecture
- **Async Engine**: High-performance concurrent scanning
- **Plugin System**: Modular architecture for extensibility
- **Strict Validation**: Fail-fast query parsing with helpful error messages
- **Backward Compatibility**: Sync plugins work with async engine
- **Resource Management**: Automatic rate limiting and connection pooling

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/kiss.git
cd kiss

# Install dependencies
pip install -r requirements.txt

# Run the application
python -m kiss
```

### Basic Usage

```bash
# Simple email lookup
python -m kiss user@example.com

# Phone number analysis
python -m kiss +1234567890

# Username enumeration
python -m kiss @johndoe

# IP address intelligence
python -m kiss 192.168.1.1

# Address geocoding
python -m kiss "123 Main St, City, Country"
```

### Advanced Queries (Planned)

```bash
# Structured queries with strict validation
email:"user@domain.com"
name:"John Doe" location:"New York, US"
phone:"+1234567890" carrier:"verizon"
username:"johndoe" platform:"twitter,instagram"
ip:"192.168.1.1" country:"US"
address:"123 Main St" city:"Boston" state:"MA"
hash:"5d41402abc4b2a76b9719d911017c592"
ssid:"MyWiFi" bssid:"00:11:22:33:44:55"
```

## Configuration

### API Keys Setup

Create a configuration file or set environment variables:

```bash
# Environment variables
export KISS_HIBP_API_KEY="your_hibp_key"
export KISS_IPINFO_API_KEY="your_ipinfo_key"
export KISS_PHONE_API_KEY="your_phone_key"

# Or create config file
cp config.example.json ~/.kiss/config.json
# Edit the file with your API keys
```

### Supported Services

- **Have I Been Pwned**: Email breach detection
- **IPInfo**: IP geolocation and network intelligence
- **VeriPhone**: Phone number validation and carrier lookup
- **OpenStreetMap**: Address geocoding
- **Gravatar**: Email avatar lookup
- **Hudson Rock**: Stealer malware detection

## Development

### Plugin Development

KISS uses a modular plugin architecture. Create custom plugins using the provided templates:

```python
from kiss.plugins.async_base import AsyncBasePlugin, PluginMetadata

class MyPlugin(AsyncBasePlugin):
    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="my_plugin",
            display_name="My Plugin",
            description="Custom intelligence gathering",
            version="1.0.0",
            category="Custom",
            supported_scan_types=["EMAIL"],
            rate_limit=60,
            timeout=30,
        )
    
    async def scan_async(self, target: str, scan_type: str, progress_callback):
        # Your plugin logic here
        return [self._create_result("Result", "value")]
```

See [Plugin Development Guide](docs/PLUGIN_DEVELOPMENT.md) for detailed instructions.

### Async Architecture

KISS is transitioning to async architecture for better performance:

- **AsyncBasePlugin**: Base class for new async plugins
- **AsyncOSINTEngine**: High-performance async scanning engine
- **Backward Compatibility**: Sync plugins automatically wrapped
- **Resource Efficiency**: Non-blocking I/O and connection pooling

### Testing

```bash
# Run unit tests
pytest tests/

# Run with coverage
pytest --cov=kiss tests/

# Run specific test
pytest tests/test_scanner.py
```

## Roadmap

### v2.1 (Current Development)
- [x] Async plugin architecture
- [x] Strict query parser with validation
- [x] Plugin template system
- [ ] Query syntax implementation
- [ ] Enhanced TUI integration

### v2.2 (Planned)
- [ ] Name-based searches (name:"John Doe" location:"New York")
- [ ] SSID/BSSID lookup implementation
- [ ] Advanced phone number parsing
- [ ] Enhanced hash type detection

### v3.0 (Future)
- [ ] Batch processing capabilities
- [ ] Export functionality (JSON, CSV, PDF)
- [ ] REST API endpoint
- [ ] Web interface
- [ ] Plugin marketplace

## Query Syntax

### Current Support
```bash
# Simple targets
user@example.com
+1234567890
192.168.1.1
@username
"123 Main St, City, Country"
```

### Planned Support
```bash
# Structured queries (strict validation)
email:"user@domain.com"
name:"John Doe" location:"New York, US"
phone:"+1234567890" carrier:"verizon"
username:"johndoe" platform:"twitter"
ip:"192.168.1.1" country:"US"
address:"123 Main St" city:"Boston" state:"MA"
hash:"5d41402abc4b2a76b9719d911017c592"
ssid:"MyWiFi" bssid:"00:11:22:33:44:55"
```

## Architecture

```
kiss/
├── kiss/                    # Core package
│   ├── plugins/            # Plugin system
│   ├── scanner/            # Query parsing and detection
│   ├── models.py           # Data models
│   ├── config.py           # Configuration management
│   ├── async_engine.py     # Async scanning engine
│   └── __main__.py        # Entry point
├── examples/               # Demo files and examples
├── tests/                  # Unit tests
├── docs/                   # Documentation
└── TODO.md                 # Development roadmap
```

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/kiss.git
cd kiss

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest

# Run linting
black kiss/
flake8 kiss/
```

### Plugin Submission

1. Fork the repository
2. Create your plugin using the template
3. Add comprehensive tests
4. Update documentation
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **Have I Been Pwned** for breach data
- **IPInfo** for IP intelligence
- **OpenStreetMap** for geocoding
- **phonenumbers** for phone validation
- The Python async community for inspiration

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/yourusername/kiss/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/kiss/discussions)
- **Examples**: [examples/](examples/)

---

<div align="center">

Built with ❤️ for the OSINT community
