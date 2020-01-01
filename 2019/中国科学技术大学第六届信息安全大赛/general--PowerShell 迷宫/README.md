公元 9102 年，M$ 神教开始密谋一场运动——利用先进的 PowerShell Core 将落后的 bash 扫进历史的垃圾堆！
>
M$ 传教现场：
>
M$ 教徒：
>
> 什么？听说你们 bash 还要记一大堆乱七八糟的命令名和他们的一大堆含义不明的参数名？<br>
康康我们的 pwsh 吧！Verb-Noun 的命名方式大大降低了记忆难度，更有全拼参数名，比什么不知所云的 -a -b 不知道高到哪里去了。
>
```bash
PS /> Import-Module -Name .\PSMaze.dll
PS /> Get-Member -?

NAME
    Get-Member
... (omitted)
```
>
> 嫌命令长？那你是一定是不知道缩写！
>
gci -> Get-ChildItem
gi  -> Get-Item
gal -> Get-Alias (滑稽)
>
围观群众：那要是用惯了 bash 的人不小心打出了熟悉的命令怎么办？
>
M$ 教徒：
>
> 你试试看
>
```bash
PS /> cd Maze:/
PS Maze:\> ls

Direction X Y Flag
--------- - - ----
     Down 0 1

PS Maze:\> cd Down
```
>
> 还能不能用？
>
随后，M$ 神教教徒拿出了杀手锏
>
> 我们的 pwsh 基于对象而不是文本，基于 .NET 实现，背后有庞大丰富的 .NET 的标准库做后盾！

```bash
PS Maze:\> (Get-ChildItem).Length
1
PS Maze:\> (Get-ChildItem)[0] | Get-Member


   TypeName: PSMaze.MazeCell
Name              MemberType   Definition
----              ----------   ----------
PSStandardMembers MemberSet    PSStandardMembers {DefaultDisplayPropertySet}
Equals            Method       bool Equals(System.Object obj)
GetHashCode       Method       int GetHashCode()
GetType           Method       type GetType()
ToString          Method       string ToString()
Direction         NoteProperty Direction Direction=Down
PSChildName       NoteProperty string PSChildName=Down
PSDrive           NoteProperty PSDriveInfo PSDrive=Maze
PSIsContainer     NoteProperty bool PSIsContainer=True
PSParentPath      NoteProperty string PSParentPath=PSMaze\Maze::\
PSPath            NoteProperty string PSPath=PSMaze\Maze::\Down
PSProvider        NoteProperty ProviderInfo PSProvider=PSMaze\Maze
Flag              Property     string Flag {get;}
X                 Property     int X {get;}
Y                 Property     int Y {get;}

PS Maze:\> using namespace System.Collections.Generic
PS Maze:\> using namespace System
PS Maze:\> $dict = [Dictionary[string, Tuple[int, int]]]::new()
PS Maze:\> Get-ChildItem | ForEach-Object { $dict.Add($_.Direction, [Tuple[int, int]]::new($_.X, $_.Y)) }
PS Maze:\> $dict

Key  Value
---  -----
Down (0, 1)
```
>
bash 教徒还是不服，为了挫败阴谋，他们决定盗取 M$ 神教藏在 PowerShell 迷宫深处的最高机密—— flag。<br>
然而 bash 教徒不屑于学习使用 PowerShell 走迷宫，于是他们请来了你，你能帮他们找到 flag 吗？<br>
hint：<br>
1. 你需要 <a href="https://github.com/PowerShell/PowerShell/blob/v6.2.3/README.md">PowerShell Core 6.2.3</a>
2. 你可能还需要了解 <a href="https://docs.microsoft.com/en-us/dotnet/api/?view=netcore-2.2">.NET Core 2.2 API</a>
3. 空 flag 为 null
4. 其他 hint 都在调皮文案里（逃
5. <a href="https://docs.microsoft.com/en-us/powershell">PowerShell文档</a>