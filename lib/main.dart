import 'dart:async';
import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'src/rust/api.dart';
import 'src/rust/frb_generated.dart';

// نموذج سجل التحميل
class DownloadHistoryItem {
  final String fileName;
  final String deviceName;
  final int totalBytes;
  final DateTime timestamp;
  final Duration duration;
  final bool isSuccess;

  DownloadHistoryItem({
    required this.fileName,
    required this.deviceName,
    required this.totalBytes,
    required this.timestamp,
    required this.duration,
    required this.isSuccess,
  });
}

// نموذج التحميل النشط
class ActiveDownloadTask {
  final int fileId;
  final String fileName;
  final String deviceName;
  final int totalBytes;
  int downloadedBytes;
  double speedMbS;
  bool isFinished;
  DateTime startTime;

  ActiveDownloadTask({
    required this.fileId,
    required this.fileName,
    required this.deviceName,
    required this.totalBytes,
    this.downloadedBytes = 0,
    this.speedMbS = 0.0,
    this.isFinished = false,
    DateTime? startTime,
  }) : startTime = startTime ?? DateTime.now();
}

// مدير التحميلات العام
class DownloadManager extends ChangeNotifier {
  static final DownloadManager instance = DownloadManager._();
  DownloadManager._();

  final List<ActiveDownloadTask> activeTasks = [];
  final List<DownloadHistoryItem> history = [];

  ActiveDownloadTask? get currentTask =>
      activeTasks.isNotEmpty ? activeTasks.firstWhere((t) => !t.isFinished, orElse: () => activeTasks.first) : null;

  void addTask(ActiveDownloadTask task) {
    activeTasks.add(task);
    notifyListeners();
  }

  void updateProgress(int fileId, int downloaded, double speed) {
    final idx = activeTasks.indexWhere((t) => t.fileId == fileId && !t.isFinished);
    if (idx != -1) {
      activeTasks[idx].downloadedBytes = downloaded;
      activeTasks[idx].speedMbS = speed;
      notifyListeners();
    }
  }

  void completeTask(int fileId, bool success) {
    final idx = activeTasks.indexWhere((t) => t.fileId == fileId && !t.isFinished);
    if (idx != -1) {
      final task = activeTasks[idx];
      task.isFinished = true;
      task.downloadedBytes = task.totalBytes;
      history.insert(
        0,
        DownloadHistoryItem(
          fileName: task.fileName,
          deviceName: task.deviceName,
          totalBytes: task.totalBytes,
          timestamp: DateTime.now(),
          duration: DateTime.now().difference(task.startTime),
          isSuccess: success,
        ),
      );
      activeTasks.removeAt(idx);
      notifyListeners();
    }
  }
}

// دالة تنسيق الأحجام التلقائية (B, KB, MB, GB)
String formatBytes(num bytes) {
  if (bytes < 1024) return "$bytes B";
  if (bytes < 1024 * 1024) return "${(bytes / 1024).toStringAsFixed(1)} KB";
  if (bytes < 1024 * 1024 * 1024) return "${(bytes / (1024 * 1024)).toStringAsFixed(2)} MB";
  return "${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB";
}

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init(forceSameCodegenVersion: false);
  runApp(const P2PManagerApp());
}

class P2PManagerApp extends StatelessWidget {
  const P2PManagerApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'DevicesManager (QUIC P2P)',
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark(useMaterial3: true).copyWith(
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.deepPurple,
          brightness: Brightness.dark,
        ),
      ),
      home: const MainTabScreen(),
    );
  }
}

class MainTabScreen extends StatefulWidget {
  const MainTabScreen({super.key});

  @override
  State<MainTabScreen> createState() => _MainTabScreenState();
}

class _MainTabScreenState extends State<MainTabScreen> {
  int _currentIndex = 0;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Column(
        children: [
          Expanded(
            child: IndexedStack(
              index: _currentIndex,
              children: const [
                TransferHomeScreen(),
                DownloadsTabScreen(),
                SettingsScreen(),
              ],
            ),
          ),
          const BottomGlobalProgressBar(),
        ],
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _currentIndex,
        onDestinationSelected: (idx) => setState(() => _currentIndex = idx),
        destinations: const [
          NavigationDestination(icon: Icon(Icons.devices), label: "Devices"),
          NavigationDestination(icon: Icon(Icons.download), label: "Downloads"),
          NavigationDestination(icon: Icon(Icons.settings), label: "Settings"),
        ],
      ),
    );
  }
}

// شريط التقدم السفلي العام
class BottomGlobalProgressBar extends StatelessWidget {
  const BottomGlobalProgressBar({super.key});

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: DownloadManager.instance,
      builder: (context, _) {
        final task = DownloadManager.instance.currentTask;
        if (task == null || task.isFinished) return const SizedBox.shrink();

        final progress = task.totalBytes > 0 ? (task.downloadedBytes / task.totalBytes).clamp(0.0, 1.0) : 0.0;

        return Container(
          color: Colors.deepPurple.shade900.withValues(alpha: 0.9),
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Expanded(
                    child: Text(
                      "Downloading: ${task.fileName}",
                      style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  Text(
                    "${formatBytes(task.downloadedBytes)} / ${formatBytes(task.totalBytes)} (${task.speedMbS.toStringAsFixed(1)} MB/s)",
                    style: const TextStyle(fontSize: 12, color: Colors.greenAccent),
                  ),
                ],
              ),
              const SizedBox(height: 6),
              LinearProgressIndicator(value: progress, minHeight: 4),
            ],
          ),
        );
      },
    );
  }
}

// ------------------- TAB 1: DEVICES -------------------

class TransferHomeScreen extends StatefulWidget {
  const TransferHomeScreen({super.key});

  @override
  State<TransferHomeScreen> createState() => _TransferHomeScreenState();
}

class _TransferHomeScreenState extends State<TransferHomeScreen> {
  bool _serverActive = false;
  String _serverInfo = "Starting server...";
  List<GuiDeviceInfo> _devices = [];
  bool _isScanning = false;

  @override
  void initState() {
    super.initState();
    _startServer();
  }

  Future<void> _startServer() async {
    try {
      final pairingStream = startGuiServer();
      setState(() {
        _serverActive = true;
        _serverInfo = "Server Active & Listening";
      });

      pairingStream.listen((event) {
        _showPairingDialog(event.deviceName, event.fingerprint);
      });

      _scanDevices();
    } catch (e) {
      setState(() {
        _serverActive = false;
        _serverInfo = "Server error: $e";
      });
    }
  }

  void _showPairingDialog(String deviceName, String fingerprint) {
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => AlertDialog(
        title: const Text("Device Pairing Request"),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text("Trust connection from: $deviceName?"),
            const SizedBox(height: 8),
            Text("Fingerprint:\n$fingerprint", style: const TextStyle(fontSize: 11, fontFamily: 'monospace')),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () {
              respondPairingDecision(accept: false);
              Navigator.pop(ctx);
            },
            child: const Text("Reject", style: TextStyle(color: Colors.redAccent)),
          ),
          ElevatedButton(
            onPressed: () {
              respondPairingDecision(accept: true);
              Navigator.pop(ctx);
              _scanDevices();
            },
            child: const Text("Accept & Trust"),
          ),
        ],
      ),
    );
  }

  Future<void> _scanDevices() async {
    setState(() => _isScanning = true);
    try {
      final list = await scanNetworkDevices();
      setState(() {
        _devices = list;
        _isScanning = false;
      });
    } catch (e) {
      setState(() => _isScanning = false);
    }
  }

  Widget _buildDeviceTile(GuiDeviceInfo dev) {
    final bool isOnline = dev.ip != "Offline";
    return Card(
      elevation: isOnline ? 2 : 0,
      color: isOnline ? null : Colors.grey.withValues(alpha: 0.08),
      margin: const EdgeInsets.symmetric(vertical: 4),
      child: ListTile(
        leading: CircleAvatar(
          backgroundColor: isOnline ? Colors.green.withValues(alpha: 0.2) : Colors.grey.withValues(alpha: 0.2),
          child: Icon(Icons.laptop, color: isOnline ? Colors.greenAccent : Colors.grey),
        ),
        title: Text(dev.name, style: TextStyle(fontWeight: FontWeight.bold, color: isOnline ? Colors.white : Colors.grey)),
        subtitle: Text(isOnline ? "Online • ${dev.ip}" : "Offline • Saved Peer",
            style: TextStyle(color: isOnline ? Colors.greenAccent : Colors.grey, fontSize: 12)),
        trailing: isOnline
            ? ElevatedButton(
                onPressed: () {
                  Navigator.push(
                    context,
                    MaterialPageRoute(builder: (_) => ExplorerBrowserScreen(device: dev)),
                  );
                },
                child: const Text("Browse"),
              )
            : const Chip(label: Text("Offline", style: TextStyle(fontSize: 11)), backgroundColor: Colors.black26),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final onlineList = _devices.where((d) => d.ip != "Offline").toList();
    final offlineList = _devices.where((d) => d.ip == "Offline").toList();

    return Scaffold(
      appBar: AppBar(title: const Text("P2P Devices Manager")),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Card(
              child: Padding(
                padding: const EdgeInsets.all(12.0),
                child: Row(
                  children: [
                    Icon(_serverActive ? Icons.check_circle : Icons.error,
                        color: _serverActive ? Colors.greenAccent : Colors.redAccent),
                    const SizedBox(width: 12),
                    Expanded(child: Text(_serverInfo, style: const TextStyle(fontWeight: FontWeight.bold))),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 12),
            ElevatedButton.icon(
              onPressed: _isScanning ? null : _scanDevices,
              icon: _isScanning
                  ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                  : const Icon(Icons.refresh),
              label: const Text("Scan Local Network"),
            ),
            const SizedBox(height: 16),
            Expanded(
              child: _devices.isEmpty && _isScanning
                  ? const Center(child: CircularProgressIndicator())
                  : _devices.isEmpty
                      ? const Center(child: Text("No devices found.", style: TextStyle(color: Colors.grey)))
                      : ListView(
                          children: [
                            if (onlineList.isNotEmpty) ...[
                              const Text("Online Devices", style: TextStyle(fontWeight: FontWeight.bold, color: Colors.greenAccent)),
                              const SizedBox(height: 6),
                              ...onlineList.map(_buildDeviceTile),
                              const SizedBox(height: 16),
                            ],
                            if (offlineList.isNotEmpty) ...[
                              const Text("Offline Devices (Known Peers)", style: TextStyle(fontWeight: FontWeight.bold, color: Colors.grey)),
                              const SizedBox(height: 6),
                              ...offlineList.map(_buildDeviceTile),
                            ],
                          ],
                        ),
            ),
          ],
        ),
      ),
    );
  }
}

// ------------------- FILE EXPLORER (NON-RECURSIVE & O(1) LOOKUP) -------------------

class ExplorerBrowserScreen extends StatefulWidget {
  final GuiDeviceInfo device;
  const ExplorerBrowserScreen({super.key, required this.device});

  @override
  State<ExplorerBrowserScreen> createState() => _ExplorerBrowserScreenState();
}

class _ExplorerBrowserScreenState extends State<ExplorerBrowserScreen> {
  List<GuiFileIndexing> _allItems = [];
  
  // خريطة سريعة لربط كل مسار مجلد بالعناصر المباشرة التي بداخله
  final Map<String, List<GuiFileIndexing>> _childrenMap = {};
  final List<GuiFileIndexing> _rootItems = [];

  // تاريخ الملاحة بالمسارات الكاملة لمنع أي تكرار
  final List<String> _pathHistory = [];
  final List<String> _titleHistory = [];

  final Set<int> _selectedIds = {};
  bool _loading = true;
  String? _errorMessage;

  @override
  void initState() {
    super.initState();
    _fetchIndex();
  }

  Future<void> _fetchIndex() async {
    setState(() {
      _loading = true;
      _errorMessage = null;
      _selectedIds.clear();
      _childrenMap.clear();
      _rootItems.clear();
      _pathHistory.clear();
      _titleHistory.clear();
    });

    try {
      final items = await getRemoteDeviceFiles(
        targetIp: widget.device.ip,
        targetName: widget.device.name,
      );

      // بناء فهرس الشجرة بمرور خطي واحد فائق السرعة O(N)
      for (final item in items) {
        if (item.parentDir == null || item.parentDir!.isEmpty) {
          _rootItems.add(item);
        } else {
          // استخراج مسار المجلد الأب الفعلي من مسار الملف
          final p = item.path;
          final sep = p.contains('\\') ? '\\' : '/';
          final lastIdx = p.lastIndexOf(sep);
          final parentPath = (lastIdx != -1) ? p.substring(0, lastIdx) : item.parentDir!;
          
          _childrenMap.putIfAbsent(parentPath, () => []).add(item);
        }
      }

      setState(() {
        _allItems = items;
        _loading = false;
      });
    } catch (e) {
      setState(() {
        _loading = false;
        _errorMessage = e.toString();
      });
    }
  }

  // جلب العناصر الحالية مباشرة بدون تكرار أو تأخير
  List<GuiFileIndexing> get _visibleItems {
    if (_allItems.isEmpty) return [];
    if (_pathHistory.isEmpty) {
      return _rootItems.isNotEmpty ? _rootItems : _allItems;
    }
    final currentPath = _pathHistory.last;
    return _childrenMap[currentPath] ?? [];
  }

  // حساب حجم المجلد بدون استدعاء عودي عبر حلقة تكرارية آمنة (Iterative BFS)
  int _calculateFolderSizeIterative(String rootFolderPath) {
    int totalBytes = 0;
    final List<String> dirsToScan = [rootFolderPath];

    while (dirsToScan.isNotEmpty) {
      final currentDir = dirsToScan.removeLast();
      final children = _childrenMap[currentDir];
      if (children != null) {
        for (final child in children) {
          if (child.isDir) {
            dirsToScan.add(child.path);
          } else {
            totalBytes += child.size.toInt();
          }
        }
      }
    }
    return totalBytes;
  }

  // جمع كافة الملفات داخل المجلد برمجياً بدون تعليق
  List<GuiFileIndexing> _getAllFilesInFolderIterative(String rootFolderPath) {
    final List<GuiFileIndexing> files = [];
    final List<String> dirsToScan = [rootFolderPath];

    while (dirsToScan.isNotEmpty) {
      final currentDir = dirsToScan.removeLast();
      final children = _childrenMap[currentDir];
      if (children != null) {
        for (final child in children) {
          if (child.isDir) {
            dirsToScan.add(child.path);
          } else {
            files.add(child);
          }
        }
      }
    }
    return files;
  }

  Future<void> _downloadSingleFile(GuiFileIndexing file) async {
    final task = ActiveDownloadTask(
      fileId: file.id.toInt(),
      fileName: file.name,
      deviceName: widget.device.name,
      totalBytes: file.size.toInt(),
    );
    DownloadManager.instance.addTask(task);

    try {
      final start = DateTime.now();
      await downloadFileFromRemote(
        targetIp: widget.device.ip,
        targetName: widget.device.name,
        fileId: file.id,
      );
      final elapsed = DateTime.now().difference(start).inMilliseconds / 1000.0;
      final speed = elapsed > 0 ? (file.size.toInt() / (1024 * 1024)) / elapsed : 0.0;
      DownloadManager.instance.updateProgress(file.id.toInt(), file.size.toInt(), speed);
      DownloadManager.instance.completeTask(file.id.toInt(), true);
    } catch (e) {
      DownloadManager.instance.completeTask(file.id.toInt(), false);
    }
  }

  void _confirmAndDownloadFolder(GuiFileIndexing folder) {
    final files = _getAllFilesInFolderIterative(folder.path);
    final totalBytes = _calculateFolderSizeIterative(folder.path);

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text("Download '${folder.name}'?"),
        content: Text(
          "Folder contains ${files.length} files.\nTotal size: ${formatBytes(totalBytes)}",
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text("Cancel")),
          ElevatedButton(
            onPressed: () {
              Navigator.pop(ctx);
              for (final f in files) {
                _downloadSingleFile(f);
              }
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(content: Text("Enqueued ${files.length} files from ${folder.name}")),
              );
            },
            child: const Text("Download All"),
          ),
        ],
      ),
    );
  }

  void _downloadSelectedItems() {
    final selectedFiles = <GuiFileIndexing>[];
    for (final id in _selectedIds) {
      final item = _allItems.firstWhere((f) => f.id.toInt() == id);
      if (item.isDir) {
        selectedFiles.addAll(_getAllFilesInFolderIterative(item.path));
      } else {
        selectedFiles.add(item);
      }
    }

    setState(() => _selectedIds.clear());
    for (final f in selectedFiles) {
      _downloadSingleFile(f);
    }
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text("Enqueued ${selectedFiles.length} files for download.")),
    );
  }

  @override
  Widget build(BuildContext context) {
    final currentTitle = _titleHistory.isEmpty ? "All Shared Roots" : _titleHistory.last;
    final visible = _visibleItems;

    int selectedBytes = 0;
    for (final id in _selectedIds) {
      final item = _allItems.firstWhere((f) => f.id.toInt() == id);
      selectedBytes += item.isDir ? _calculateFolderSizeIterative(item.path) : item.size.toInt();
    }

    return Scaffold(
      appBar: AppBar(
        title: Text("Explorer: ${widget.device.name}"),
        actions: [
          if (_selectedIds.isNotEmpty)
            IconButton(
              icon: const Icon(Icons.clear_all),
              onPressed: () => setState(() => _selectedIds.clear()),
              tooltip: "Clear Selection",
            ),
          IconButton(icon: const Icon(Icons.refresh), onPressed: _fetchIndex),
        ],
      ),
      body: Column(
        children: [
          // شريط التنقل العلوي
          Container(
            color: Colors.white.withValues(alpha: 0.05),
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            child: Row(
              children: [
                IconButton(
                  icon: const Icon(Icons.arrow_upward),
                  onPressed: _pathHistory.isEmpty
                      ? null
                      : () {
                          setState(() {
                            _pathHistory.removeLast();
                            _titleHistory.removeLast();
                          });
                        },
                  tooltip: "Up one level",
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Text("📁 $currentTitle (${visible.length} items)",
                      style: const TextStyle(fontWeight: FontWeight.bold)),
                ),
              ],
            ),
          ),
          Expanded(
            child: _loading
                ? const Center(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        CircularProgressIndicator(),
                        SizedBox(height: 16),
                        Text("Retrieving file tree..."),
                      ],
                    ),
                  )
                : _errorMessage != null
                    ? Center(child: Text(_errorMessage!))
                    : visible.isEmpty
                        ? const Center(child: Text("Empty directory."))
                        : ListView.builder(
                            itemCount: visible.length,
                            itemBuilder: (context, idx) {
                              final item = visible[idx];
                              final isDir = item.isDir;
                              final itemId = item.id.toInt();
                              final isSelected = _selectedIds.contains(itemId);
                              final sizeText = isDir ? "Folder" : formatBytes(item.size.toInt());

                              return ListTile(
                                selected: isSelected,
                                leading: Checkbox(
                                  value: isSelected,
                                  onChanged: (val) {
                                    setState(() {
                                      if (val == true) {
                                        _selectedIds.add(itemId);
                                      } else {
                                        _selectedIds.remove(itemId);
                                      }
                                    });
                                  },
                                ),
                                title: Row(
                                  children: [
                                    Icon(isDir ? Icons.folder : Icons.insert_drive_file,
                                        color: isDir ? Colors.amber : Colors.blueAccent, size: 22),
                                    const SizedBox(width: 8),
                                    Expanded(child: Text(item.name)),
                                  ],
                                ),
                                subtitle: Text(sizeText),
                                trailing: isDir
                                    ? IconButton(
                                        icon: const Icon(Icons.folder_zip),
                                        tooltip: "Download Entire Folder",
                                        onPressed: () => _confirmAndDownloadFolder(item),
                                      )
                                    : IconButton(
                                        icon: const Icon(Icons.download),
                                        onPressed: () => _downloadSingleFile(item),
                                      ),
                                onTap: isDir
                                    ? () {
                                        setState(() {
                                          _pathHistory.add(item.path);
                                          _titleHistory.add(item.name);
                                        });
                                      }
                                    : () {
                                        setState(() {
                                          isSelected ? _selectedIds.remove(itemId) : _selectedIds.add(itemId);
                                        });
                                      },
                              );
                            },
                          ),
          ),
          // شريط التحديد المتعدد السفلي
          if (_selectedIds.isNotEmpty)
            Container(
              color: Colors.deepPurple.shade800,
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      "Selected: ${_selectedIds.length} items (${formatBytes(selectedBytes)})",
                      style: const TextStyle(fontWeight: FontWeight.bold),
                    ),
                  ),
                  ElevatedButton.icon(
                    style: ElevatedButton.styleFrom(backgroundColor: Colors.green),
                    onPressed: _downloadSelectedItems,
                    icon: const Icon(Icons.download),
                    label: const Text("Download Selected"),
                  ),
                ],
              ),
            ),
        ],
      ),
    );
  }
}

// ------------------- TAB 2: DOWNLOADS & HISTORY -------------------

class DownloadsTabScreen extends StatelessWidget {
  const DownloadsTabScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return DefaultTabController(
      length: 2,
      child: Scaffold(
        appBar: AppBar(
          title: const Text("Downloads"),
          bottom: const TabBar(
            tabs: [
              Tab(icon: Icon(Icons.sync), text: "Active Transfers"),
              Tab(icon: Icon(Icons.history), text: "History"),
            ],
          ),
        ),
        body: const TabBarView(
          children: [
            ActiveDownloadsList(),
            DownloadHistoryList(),
          ],
        ),
      ),
    );
  }
}

class ActiveDownloadsList extends StatelessWidget {
  const ActiveDownloadsList({super.key});

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: DownloadManager.instance,
      builder: (context, _) {
        final tasks = DownloadManager.instance.activeTasks;
        if (tasks.isEmpty) {
          return const Center(child: Text("No active downloads."));
        }

        return ListView.builder(
          itemCount: tasks.length,
          itemBuilder: (context, idx) {
            final t = tasks[idx];
            final progress = t.totalBytes > 0 ? (t.downloadedBytes / t.totalBytes).clamp(0.0, 1.0) : 0.0;

            return Card(
              margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              child: Padding(
                padding: const EdgeInsets.all(12.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(t.fileName, style: const TextStyle(fontWeight: FontWeight.bold)),
                    const SizedBox(height: 4),
                    Text("From: ${t.deviceName} • ${formatBytes(t.downloadedBytes)} / ${formatBytes(t.totalBytes)}",
                        style: const TextStyle(fontSize: 12, color: Colors.grey)),
                    const SizedBox(height: 8),
                    LinearProgressIndicator(value: progress),
                    const SizedBox(height: 6),
                    Align(
                      alignment: Alignment.centerRight,
                      child: Text("${t.speedMbS.toStringAsFixed(1)} MB/s",
                          style: const TextStyle(color: Colors.greenAccent, fontSize: 12)),
                    ),
                  ],
                ),
              ),
            );
          },
        );
      },
    );
  }
}

class DownloadHistoryList extends StatelessWidget {
  const DownloadHistoryList({super.key});

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: DownloadManager.instance,
      builder: (context, _) {
        final history = DownloadManager.instance.history;
        if (history.isEmpty) {
          return const Center(child: Text("No download history yet."));
        }

        return ListView.builder(
          itemCount: history.length,
          itemBuilder: (context, idx) {
            final item = history[idx];
            return ListTile(
              leading: Icon(
                item.isSuccess ? Icons.check_circle : Icons.error,
                color: item.isSuccess ? Colors.green : Colors.red,
              ),
              title: Text(item.fileName),
              subtitle: Text(
                "Peer: ${item.deviceName} • Size: ${formatBytes(item.totalBytes)} • Took: ${item.duration.inSeconds}s",
                style: const TextStyle(fontSize: 12),
              ),
              trailing: Text(
                "${item.timestamp.hour}:${item.timestamp.minute.toString().padLeft(2, '0')}",
                style: const TextStyle(color: Colors.grey, fontSize: 11),
              ),
            );
          },
        );
      },
    );
  }
}

// ------------------- TAB 3: SETTINGS -------------------

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  List<String> _shareRoots = [];
  String _downloadDir = "./downloads";
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _loadSettings();
  }

  Future<void> _loadSettings() async {
    try {
      final roots = await getShareRoots();
      setState(() {
        _shareRoots = roots;
        _loading = false;
      });
    } catch (e) {
      setState(() => _loading = false);
    }
  }

  Future<void> _pickShareFolder() async {
    String? selected = await FilePicker.platform.getDirectoryPath();
    if (selected != null && !_shareRoots.contains(selected)) {
      final updated = List<String>.from(_shareRoots)..add(selected);
      await updateShareRoots(newRoots: updated);
      setState(() => _shareRoots = updated);
    }
  }

  Future<void> _pickDownloadFolder() async {
    String? selected = await FilePicker.platform.getDirectoryPath();
    if (selected != null) {
      setState(() => _downloadDir = selected);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text("Download path updated.")),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text("Settings")),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              padding: const EdgeInsets.all(16.0),
              children: [
                Card(
                  child: ListTile(
                    leading: const Icon(Icons.download_for_offline, color: Colors.greenAccent),
                    title: const Text("Download Destination Folder"),
                    subtitle: Text(_downloadDir),
                    trailing: ElevatedButton(
                      onPressed: _pickDownloadFolder,
                      child: const Text("Change"),
                    ),
                  ),
                ),
                const SizedBox(height: 16),
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(12.0),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            const Text("Allowed Shared Roots", style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                            ElevatedButton.icon(
                              onPressed: _pickShareFolder,
                              icon: const Icon(Icons.add),
                              label: const Text("Add"),
                            ),
                          ],
                        ),
                        const SizedBox(height: 8),
                        ..._shareRoots.map((p) => ListTile(
                              dense: true,
                              leading: const Icon(Icons.folder, color: Colors.amber),
                              title: Text(p, style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
                              trailing: IconButton(
                                icon: const Icon(Icons.delete_outline, color: Colors.redAccent),
                                onPressed: () async {
                                  final updated = List<String>.from(_shareRoots)..remove(p);
                                  await updateShareRoots(newRoots: updated);
                                  setState(() => _shareRoots = updated);
                                },
                              ),
                            )),
                      ],
                    ),
                  ),
                ),
              ],
            ),
    );
  }
}
