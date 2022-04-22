# Yara Engine

> A C++ Yara Rule Runner, making use of the [Yara C API](https://yara.readthedocs.io/en/stable/capi.html). 

![](/images/yaraengine.gif)

## Usage
```
~ YaraEngine ~

PS> YaraEngine.exe <path to rule> <pid> [-v]
```

### From Directory
```
YaraEngine c:\rules-master\ 22492
```

### From File
```
YaraEngine c:\cobalt-strike.yar 22492
```
