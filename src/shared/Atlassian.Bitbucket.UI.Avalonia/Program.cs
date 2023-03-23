﻿using System;
using System.Diagnostics;
using System.Threading;
using Atlassian.Bitbucket.UI.Commands;
using Atlassian.Bitbucket.UI.Controls;
using Avalonia;
using GitCredentialManager;
using GitCredentialManager.UI;

namespace Atlassian.Bitbucket.UI
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            // If we have no arguments then just start the app with the test window.
            if (args.Length == 0)
            {
                BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
                return;
            }

            // Create the dispatcher on the main thread. This is required
            // for some platform UI services such as macOS that mandates
            // all controls are created/accessed on the initial thread
            // created by the process (the process entry thread).
            Dispatcher.Initialize();

            // Run AppMain in a new thread and keep the main thread free
            // to process the dispatcher's job queue.
            var appMain = new Thread(AppMain) {Name = nameof(AppMain)};
            appMain.Start(args);

            // Process the dispatcher job queue (aka: message pump, run-loop, etc...)
            // We must ensure to run this on the same thread that it was created on
            // (the main thread) so we cannot use any async/await calls between
            // Dispatcher.Create and Run.
            Dispatcher.MainThread.Run();

            // Execution should never reach here as AppMain terminates the process on completion.
            throw new InvalidOperationException("Main dispatcher job queue shutdown unexpectedly");
        }

        private static void AppMain(object o)
        {
            string[] args = (string[]) o;

            // Set the session id (sid) for the helper process, to be
            // used when TRACE2 tracing is enabled.
            ProcessManager.CreateSid();
            using (var context = new CommandContext())
            using (var app = new HelperApplication(context))
            {
                // Initialize TRACE2 system
                context.Trace2.Initialize(DateTimeOffset.UtcNow);

                // Write the start and version events
                context.Trace2.Start(context.ApplicationPath, args, "main");

                app.RegisterCommand(new CredentialsCommandImpl(context));

                int exitCode = app.RunAsync(args)
                    .ConfigureAwait(false)
                    .GetAwaiter()
                    .GetResult();

                context.Trace2.Stop(exitCode, Thread.CurrentThread.Name);
                Environment.Exit(exitCode);
            }
        }

        public static AppBuilder BuildAvaloniaApp()
            => AppBuilder.Configure(() => new AvaloniaApp(() => new TesterWindow()))
                .UsePlatformDetect()
                .LogToTrace();
    }
}
