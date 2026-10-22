using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ResetExplode;

/// <summary>
/// Pasta de trabalho só de Administradores/SYSTEM em %ProgramData%. Instaladores e drivers extraídos aqui não podem ser trocados por
/// um processo comum entre a verificação e a execução (em %TEMP% qualquer processo do usuário consegue).
/// </summary>
internal static class AdminDir
{
    private static readonly SecurityIdentifier Admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier System_ = new(WellKnownSidType.LocalSystemSid, null);

    /// <summary>Devolve %ProgramData%\ResetExplode\&lt;name&gt;, nova e vazia.</summary>
    public static string Fresh(string name)
    {
        string root = Locked(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ResetExplode"));
        string dir = Path.Combine(root, name);
        if (Directory.Exists(dir)) Directory.Delete(dir, true);
        return Locked(dir);
    }

    private static string Locked(string path)
    {
        var di = new DirectoryInfo(path);
        if (di.Exists)
        {
            var owner = di.GetAccessControl().GetOwner(typeof(SecurityIdentifier));
            if (!Admins.Equals(owner) && !System_.Equals(owner))
                throw new InvalidOperationException($"A pasta {path} pertence a outro usuário; recusei usá-la.");
        }

        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(true, false); // sem herança: nada de "Users" vindo do ProgramData
        foreach (var sid in new[] { Admins, System_ })
            sec.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        if (di.Exists) di.SetAccessControl(sec); else di.Create(sec);
        return path;
    }
}
