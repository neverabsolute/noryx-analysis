using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Noryx.Agent;

internal static class BoundedInspectionQueue
{
	internal static void Run<T, TWorker>(IEnumerable<T> source, Func<TWorker> create, Action<TWorker, T> inspect, Action<T, Exception> failed, int concurrency = 2) where TWorker : IDisposable
	{
		if (concurrency < 1 || concurrency > 8)
		{
			throw new ArgumentOutOfRangeException("concurrency");
		}
		BlockingCollection<T> queue = new BlockingCollection<T>(256);
		try
		{
			CancellationTokenSource abort = new CancellationTokenSource();
			try
			{
				Task[] tasks = (from _ in Enumerable.Range(0, concurrency)
					select Task.Run(delegate
					{
						try
						{
							using TWorker arg = create();
							foreach (T item in queue.GetConsumingEnumerable(abort.Token))
							{
								try
								{
									inspect(arg, item);
								}
								catch (Exception arg2)
								{
									failed(item, arg2);
								}
							}
						}
						catch
						{
							abort.Cancel();
							throw;
						}
					})).ToArray();
				Exception ex = null;
				try
				{
					foreach (T item2 in source)
					{
						queue.Add(item2, abort.Token);
					}
				}
				catch (Exception ex2)
				{
					ex = ex2;
				}
				finally
				{
					queue.CompleteAdding();
				}
				Task.WaitAll(tasks);
				if (ex != null)
				{
					throw ex;
				}
			}
			finally
			{
				if (abort != null)
				{
					((IDisposable)abort).Dispose();
				}
			}
		}
		finally
		{
			if (queue != null)
			{
				((IDisposable)queue).Dispose();
			}
		}
	}
}
