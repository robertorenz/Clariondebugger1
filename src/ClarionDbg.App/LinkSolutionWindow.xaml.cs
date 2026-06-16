using System.IO;
using System.Windows;
using Clarion.SourceResolution;
using Microsoft.Win32;

namespace ClarionDbg.App;

/// <summary>
/// First-open handshake: links a .sln to a chosen Clarion version (and, optionally,
/// an explicit ClarionProperties.xml for non-default ConfigDir installs / a forced
/// configuration). On Save it produces a <see cref="SolutionAssociation"/> the caller
/// persists, plus the version + properties path needed to build the resolver.
/// </summary>
public partial class LinkSolutionWindow : Window
{
    const string AutoConfig = "Auto-detect";

    readonly string _exePath;

    public string SolutionPath { get; private set; } = "";
    public ClarionCompilerVersion? Version { get; private set; }
    public string PropertiesFile { get; private set; } = "";
    public SolutionAssociation? Association { get; private set; }

    /// <summary>One pickable (install, version) pair; ToString drives the combo display.</summary>
    sealed record VersionChoice(ClarionInstallation Install, ClarionCompilerVersion Version)
    {
        public override string ToString() => $"{Version.Name}   (IDE {Install.IdeVersion})";
    }

    public LinkSolutionWindow(string slnPath, string exePath)
    {
        InitializeComponent();
        _exePath = exePath;
        TxtSln.Text = slnPath;

        CmbConfig.ItemsSource = new[] { AutoConfig, "Debug", "Release" };
        CmbConfig.SelectedIndex = 0;

        ReloadVersions();
    }

    /// <summary>Populate the version list. With a Properties override set, parse that
    /// explicit ClarionProperties.xml (non-default ConfigDir); otherwise use the default
    /// AppData detection. Most recent version is preselected.</summary>
    void ReloadVersions()
    {
        var overridePath = TxtProps.Text.Trim();
        List<VersionChoice> choices;

        if (overridePath.Length > 0)
        {
            var install = File.Exists(overridePath)
                ? ClarionInstallationDetector.ParseInstallationFromPropertiesPath(overridePath)
                : null;
            if (install == null)
            {
                CmbVersion.ItemsSource = null;
                TxtNote.Text = "Couldn't read versions from that ClarionProperties.xml.";
                BtnSave.IsEnabled = false;
                return;
            }
            choices = install.CompilerVersions.Select(v => new VersionChoice(install, v)).ToList();
        }
        else
        {
            choices = ClarionInstallationDetector.DetectInstallations()
                .SelectMany(i => i.CompilerVersions.Select(v => new VersionChoice(i, v)))
                .ToList();
        }

        CmbVersion.ItemsSource = choices;
        if (choices.Count > 0)
        {
            CmbVersion.SelectedIndex = 0;            // most recent install first
            TxtNote.Text = "";
            BtnSave.IsEnabled = true;
        }
        else
        {
            TxtNote.Text = overridePath.Length > 0
                ? "That ClarionProperties.xml lists no usable versions."
                : "No Clarion installation detected. Skip to use the legacy source search.";
            BtnSave.IsEnabled = false;
        }
    }

    void BrowseProps_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Filter = "ClarionProperties.xml|ClarionProperties.xml|XML files (*.xml)|*.xml|All files (*.*)|*.*"
        };
        if (!string.IsNullOrEmpty(TxtProps.Text))
        {
            try { dlg.InitialDirectory = Path.GetDirectoryName(TxtProps.Text); } catch { }
        }
        if (dlg.ShowDialog() == true) { TxtProps.Text = dlg.FileName; ReloadVersions(); }
    }

    void TxtProps_LostFocus(object sender, RoutedEventArgs e) => ReloadVersions();

    void BrowseSln_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Filter = "Clarion solution (*.sln)|*.sln" };
        if (!string.IsNullOrEmpty(TxtSln.Text))
        {
            try { dlg.InitialDirectory = Path.GetDirectoryName(TxtSln.Text); } catch { }
        }
        if (dlg.ShowDialog() == true) TxtSln.Text = dlg.FileName;
    }

    void Save_Click(object sender, RoutedEventArgs e)
    {
        var sln = TxtSln.Text.Trim();
        if (!File.Exists(sln)) { TxtNote.Text = "That solution file doesn't exist."; return; }
        if (CmbVersion.SelectedItem is not VersionChoice choice) { TxtNote.Text = "Pick a Clarion version."; return; }

        var cfg = CmbConfig.SelectedItem as string;
        var configOverride = string.Equals(cfg, AutoConfig) ? null : cfg;

        // When a Properties override is set, the chosen install was parsed from it,
        // so its PropertiesPath already points at the override file. Persist that path
        // in the sidecar only for the override case; default installs stay null so
        // reopen re-detects by version name from AppData.
        var overridePath = TxtProps.Text.Trim();
        bool usingOverride = overridePath.Length > 0;

        SolutionPath = sln;
        Version = choice.Version;
        PropertiesFile = choice.Install.PropertiesPath;
        Association = new SolutionAssociation
        {
            VersionName = choice.Version.Name,
            PropertiesFile = usingOverride ? overridePath : null,
            ConfigurationOverride = configOverride,
            ExePath = _exePath,
        };
        DialogResult = true;
    }

    void Skip_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
