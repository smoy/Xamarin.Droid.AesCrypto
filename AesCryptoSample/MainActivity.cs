using Android.Content;
using Android.Runtime;
using Android.Views;
using Android.Widget;
using Android.OS;

using Xunit.Sdk;
using Xunit.Runners.UI;
using Android.App;
using System.Reflection;

namespace AesCryptoSample
{
  [Activity (Label = "xUnit Android Runner", MainLauncher = true, Theme = "@android:style/Theme.Material.Light")]
  public class MainActivity : RunnerActivity
  {

    protected override void OnCreate (Bundle bundle)
    {
      AesTest.context = this;

      // tests can be inside the main assembly
      AddTestAssembly (Assembly.GetExecutingAssembly ());

      AddExecutionAssembly (typeof (ExtensibilityPointFactory).Assembly);
      // or in any reference assemblies     

      //AddTestAssembly(typeof(PortableTests).Assembly);
      // or in any assembly that you load (since JIT is available)

      // you cannot add more assemblies once calling base
      base.OnCreate (bundle);
    }
  }
}


