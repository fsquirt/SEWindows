using System;
using System.IO;
using System.Text;

/// <summary>
/// 一个自定义的TextWriter，它将写入的行重定向到一个Action委托。
/// 这使我们能够捕获Console.WriteLine的输出并将其发送到UI。
/// </summary>
public class LabelTextWriter : TextWriter
{
    // 这个委托将指向我们窗体中的日志更新方法
    private readonly Action<string> _writeAction;

    public LabelTextWriter(Action<string> writeAction)
    {
        _writeAction = writeAction ?? throw new ArgumentNullException(nameof(writeAction));
    }

    // Console.WriteLine(string) 最终会调用这个方法
    public override void WriteLine(string value)
    {
        // 当Console.WriteLine被调用时，我们执行传入的Action
        // 把接收到的字符串传递出去
        _writeAction(value);
    }

    // 我们必须重写这个属性
    public override Encoding Encoding => Encoding.UTF8;
}