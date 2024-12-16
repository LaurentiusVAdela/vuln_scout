def parse_requirements(file_path:str):
    dependencies = []
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Expecting format: package==version
            parts = line.split("==")
            if len(parts) == 2:
                name, version = parts[0].strip(), parts[1].strip()
                dependencies.append({"name": name, "version": version})
            else:
                # If format is different, you could log a waring or handle differently
                pass
    return dependencies
