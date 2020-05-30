#ifndef RAW_H
#define RAW_H

class Capture
{
public:
    explicit Capture();
    ~Capture();

    void start(int deviceIndex);
    bool isRunning(void);
protected:
    bool m_running;
};

#endif // RAW_H
