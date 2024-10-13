# visual studio

1. visualstudio.microsoft.com/downloads
2. tools for visual studio
3. build tools for visual studio
4. continue
5. workloads
6. desktop development with C++
7. individual components
8. compilers, build tools, and runtimes
9. MSVC VS C++ ARM64/ARM64EC build tools
10. install
11. continue
12. close
13. start
14. visual studio
15. developer powershell for VS

~~~
set-location ice_repro\linker\linkrepro
~~~

for `link.rsp` remove one of these:

~~~
"/wbrdcfg:.\Windows.Media.Protection.PlayReady.dll.wbrd"
"/wbrddll:.\warbird.dll"
~~~

then:

~~~
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
Launch-VsDevShell.ps1 -Arch arm64 -HostArch amd64
Get-Command link | Format-List
$env:OBJECT_ROOT = '.'
link '@link.rsp'
~~~

result:

~~~
Windows.Media.Protection.PlayReady.dll
Windows.Media.Protection.PlayReady.pdb
~~~
